use crate::routines;
use crate::action::{DAction, AcType};
use crate::browser::BrowserCallbacks;
use crate::context::{DContext, str_hex_to_utf8, STATE_EXIT, STATE_ZERO};
use crate::debot_abi::DEBOT_ABI;
use ton_client_rs::{TonClient, TonError, TonErrorKind, TonAddress, ResultOfLocalRun, JsonValue, Ed25519KeyPair};
use std::collections::VecDeque;

fn create_client(url: &str) -> Result<TonClient, String> {
    TonClient::new_with_base_url(url)
        .map_err(|e| format!("failed to create tonclient: {}", e.to_string()))
}

pub fn load_ton_address(addr: &str) -> Result<TonAddress, String> {
    TonAddress::from_str(addr)
        .map_err(|e| format!("failed to parse address: {}", e.to_string()))
}

pub type DState = serde_json::Value;

const OPTION_ABI: u8 = 1;
const OPTION_TARGET_ABI: u8 = 2;
const OPTION_TARGET_ADDR: u8 = 4;

pub struct DEngine {
    abi: String,
    addr: TonAddress,
    ton: TonClient,
    state: DState,
    state_machine: Vec<DContext>,
    curr_state: u8,
    prev_state: u8,
    target_addr: Option<TonAddress>,
    target_abi: Option<String>,
    browser: Box<dyn BrowserCallbacks>,
}

impl DEngine {
    pub fn new(
        addr: TonAddress,
        abi: Option<String>,
        url: &str,
        browser: Box<dyn BrowserCallbacks>,
    ) -> Self {
        DEngine::new_with_client(addr, abi, create_client(url).unwrap(), browser)
    }

    pub fn new_with_client(
        addr: TonAddress,
        abi: Option<String>,
        ton: TonClient,
        browser: Box<dyn BrowserCallbacks>
    ) -> Self {
        DEngine { 
            abi: abi.unwrap_or(DEBOT_ABI.to_owned()),
            addr,
            ton,
            state: json!({}),
            state_machine: vec![],
            curr_state : STATE_EXIT,
            prev_state : STATE_ZERO,
            target_addr: None,
            target_abi: None,
            browser,
        }
    }

    pub fn fetch(&mut self) -> Result<(), String> {
        self.state_machine = self.fetch_state()?;
        Ok(())
    }

    fn fetch_state(&mut self) -> Result<Vec<DContext>, String> {
        self.load_state()?;
        let mut result = self.run_get("fetch")?;
        let context_vec: Vec<DContext> = serde_json::from_value(result.output["contexts"].take())
            .unwrap();
        Ok(context_vec)
    }

    pub fn start(&mut self) -> Result<(), String> {
        self.state_machine = self.fetch_state()?;

        // TODO: do we need to call `start` func?
        //let start_act = DAction::new_with_name("start");
        //self.run_action(&start_act)?;

        self.switch_state(STATE_ZERO)
    }

    pub fn execute_action(&mut self, act: &DAction) -> Result<(), String> {
        self.handle_action(&act)
            .and_then(|_| self.switch_state(act.to))
            .or_else (|e| {
                self.browser.log(format!("Debot action failed: {}. Return to previous state.\n", e));
                self.switch_state(self.prev_state)
            })
    }
    
    fn handle_action(
        &mut self,
        a: &DAction,
    ) -> Result<Option<Vec<DAction>>, String> {
        match a.action_type {
            AcType::Empty => {
                debug!("empty action: {}", a.name);
                Ok(None)
            },
            AcType::RunAction => {
                debug!("run_action: {}", a.name);
                self.run_action(&a)
            },
            AcType::RunMethod => {
                debug!("run_getmethod: {}", a.func_attr().unwrap());
                let args: Option<JsonValue> = if let Some(getter) = a.args_attr() {
                    let res = self.run_debot(&getter, None)?;
                    Some(res.into())
                } else {
                    None
                };
                self.run_getmethod(&a.func_attr().unwrap(), args, &a.name)?;
                Ok(None)
            },
            AcType::SendMsg => {
                debug!("sendmsg: {}", a.name);
                let keys = if a.sign_by_user() {
                    let mut keys = Ed25519KeyPair::zero();
                    self.browser.load_key(&mut keys);
                    Some(keys)
                } else {
                    None
                };
                let args: Option<JsonValue> = if a.misc != /*empty cell*/"te6ccgEBAQEAAgAAAA==" {
                    Some(json!({ "arg1": a.misc }).into())
                } else {
                    None
                };
                let result = self.run_sendmsg(&a.name, args, keys)?;
                self.browser.log(format!("Success.\nResult: {}", result));
                Ok(None)
            },            
            AcType::Invoke => {
                debug!("invoke debot: run {}", a.name);
                let invoke_args = self.run_debot(&a.name, None)?;
                debug!("{}", invoke_args);
                let debot_addr = load_ton_address(invoke_args["debot"].as_str().unwrap())?;
                let debot_action: DAction = serde_json::from_value(invoke_args["action"].clone()).unwrap();
                debug!("invoke debot: {}, action name: {}", &debot_addr, debot_action.name);
                self.browser.invoke_debot(debot_addr, debot_action)?;
                
                Ok(None)
            },
            AcType::Print => {
                let label = if let Some(fargs) = a.format_args() {
                    let params = self.run_debot(
                        &fargs,
                        Some(json!({"arg1": a.misc}).into())
                    )?;
                    routines::format_string(&a.name, &params)
                } else {
                    a.name.clone()
                };
                self.browser.log(label);
                Ok(None)
            },
            _ => {
                self.browser.log("unsupported action type".to_owned());
                Ok(None)
            },
        }
    }

    fn switch_state(&mut self, state_to: u8) -> Result<(), String> {
        debug!("switching to {}", state_to);
        if state_to == STATE_EXIT {
            let quit_context = DContext::new(String::new(), vec![], STATE_EXIT as u8);
            self.browser.switch(&quit_context);
        } else if state_to != self.curr_state {
            let mut state_to = state_to;
            self.prev_state = self.curr_state;
            self.curr_state = state_to;
            let mut next_ctx = DContext::new_quit();
            let mut instant_switch = true;
            while instant_switch {
                // TODO: restrict cyclic switches
                next_ctx = self.state_machine[state_to as usize].clone();
                self.browser.log(next_ctx.desc.clone());
                instant_switch = self.execute_instant_actions(&mut next_ctx)?;
                state_to = self.curr_state;
                debug!("instant_switch = {}, state_to = {}", instant_switch, state_to);
            }
            self.browser.switch(&next_ctx);
        }
        Ok(())
    }

    fn execute_instant_actions(&mut self, ctx: &mut DContext) -> Result<bool, String> {
        let mut result_actions = vec![];
        // find, execute and remove instant action from context.
        // if instant action returns new actions then execute them and insert into context.
        for action in &ctx.actions {
            let mut sub_actions = VecDeque::new();
            sub_actions.push_back(action.clone());
            while let Some(act) = sub_actions.pop_front() {
                if act.is_instant() {
                    self.handle_action(&act)?.and_then(|vec| {
                        vec.iter().for_each(|a| sub_actions.push_back(a.clone()));
                        Some(())
                    });
                    // if instant action wants to switch context then exit and do switch.
                    if act.to != self.curr_state {
                        self.curr_state = act.to;
                        return Ok(true);
                    }
                } else {
                    result_actions.push(act);
                }
            }
        }
        ctx.actions = result_actions;
        Ok(false)
    }

    fn run_get(&mut self, name: &str) -> Result<ResultOfLocalRun, String> {
        let res = self.run(false, name, None, true, false)?;
        Ok(res)
    }

    fn run_debot(&mut self, name: &str, args: Option<JsonValue>) -> Result<serde_json::Value, String> {
        debug!("run_debot {}, args: {}", name, if args.is_some() { args.clone().unwrap() } else { json!({}).into() });
        let res = self.run(false, name, args, true, true)?;
        self.state = res.account.unwrap();
        Ok(res.output)
    }

    fn run_action(&mut self, action: &DAction) -> Result<Option<Vec<DAction>>, String> {
        let args = self.query_action_args(action)?;

        let mut output = self.run_debot(&action.name, args)?;

        let action_vec: Option<Vec<DAction>> = match output.is_null() {
            false => Some(serde_json::from_value(output["actions"].take()).unwrap()),
            true => None,
        };

        if let Some(actions) = action_vec {
            let mut result_vec = vec![];
            for act in actions {
                match act.action_type {
                    AcType::CallEngine => {
                        let args = if let Some(args_getter) = act.args_attr() {
                            let args = self.run_debot(&args_getter, None)?;
                            args.to_string()
                        } else {
                            act.desc.clone()
                        };
                        let res = self.call_routine(&act.name, &args)?;
                        let setter = act.func_attr().unwrap();
                        self.run_debot(&setter, Some(json!({"arg1": res}).into()))?;
                    },
                    _ => result_vec.push(act),
                }
            }
            Ok(Some(result_vec))
        } else {
            Ok(None)
        }
    }

    fn run_sendmsg(
        &mut self,
        name: &str,
        args: Option<JsonValue>,
        keys: Option<Ed25519KeyPair>,
    ) -> Result<serde_json::Value, String> {
        let result = self.run_debot(name, args)?;
        let dest = result["dest"].as_str().unwrap();
        let body = result["body"].as_str().unwrap();

        let res = self.ton.contracts.decode_input_message_body(
            self.target_abi.clone().unwrap().into(),
            &base64::decode(body).unwrap(),
            true,
        ).map_err(|e| format!("failed to decode msg body: {}", e))?;

        debug!("calling {} at address {}", res.function, dest);
        debug!("args: {}", res.output);
        self.call_target(dest, &res.function, res.output.into(), keys)
    }

    fn run_getmethod(
        &mut self,
        getmethod: &str,
        args: Option<JsonValue>,
        result_handler: &str,
    ) -> Result<serde_json::Value, String> {
        self.update_options()?;
        let result = self.run(true, getmethod, args, false, false)?;
        self.run_debot(result_handler, Some(result.output.into()))
    }

    #[allow(dead_code)]
    pub fn version(&mut self) -> Result<String, String> {
        self.run_get("getVersion").map(|res| res.output.to_string())
    }

    fn load_state(&mut self) -> Result<String, String> {
        let result = self.run(false, "getVersion", None, false, true)?;
        let name_hex = result.output["name"]
            .as_str()
            .unwrap();
        let ver_str = result.output["semver"]
            .as_str()
            .unwrap()
            .trim_start_matches("0x");
        let name = str_hex_to_utf8(name_hex).unwrap();
        let ver = u32::from_str_radix(ver_str, 16).unwrap();
        
        self.state = result.account.unwrap();
        self.browser.log(format!("{}, version {}.{}.{}", name, ( ver >> 16) as u8, ( ver >> 8) as u8, ver as u8));
        self.update_options()?;
        Ok(result.output.to_string())
    }

    fn update_options(&mut self) -> Result<(), String> {
        let params = self.run_get("getDebotOptions")?;
        let opt_str = params.output["options"].as_str().unwrap();
        let options = u8::from_str_radix(
            opt_str.trim_start_matches("0x"),
            16,
        ).unwrap();
        if options & OPTION_ABI != 0 {
            self.abi = str_hex_to_utf8(
                params.output["debotAbi"].as_str().unwrap()
            ).ok_or("cannot convert hex string to debot abi")?;
        }
        if options & OPTION_TARGET_ABI != 0 {
            self.target_abi = str_hex_to_utf8(
                params.output["targetAbi"].as_str().unwrap()
            );
        }
        if (options & OPTION_TARGET_ADDR) != 0 {
            let addr = params.output["targetAddr"].as_str().unwrap();
            self.target_addr = Some(load_ton_address(addr)?);
        }
        Ok(())
    }

    fn query_action_args(&self, act: &DAction) -> Result<Option<JsonValue>, String> {
        let args: Option<JsonValue> = if act.misc != /*empty cell*/"te6ccgEBAQEAAgAAAA==" {
            Some(json!({ "arg1": act.misc }).into())
        } else {
            let abi_json: serde_json::Value = serde_json::from_str(&self.abi).unwrap();
            let functions = abi_json["functions"].as_array().unwrap();
            let func = functions.iter().find(|f| f["name"].as_str().unwrap() == act.name)
                .ok_or(format!("action not found"))?;
            let arguments = func["inputs"].as_array().unwrap();
            let mut args_json = json!({});
            for arg in arguments {
                let arg_name = arg["name"].as_str().unwrap();
                let prefix = "enter ".to_owned() + arg_name;
                let mut value = String::new();
                self.browser.input(&prefix, &mut value);
                if arg["type"].as_str().unwrap() == "bytes" {
                    value = hex::encode(value.as_bytes());
                }
                args_json[arg_name] = json!(&value);
            }
            Some(args_json.into())
        };
        Ok(args)
    }

    fn get_target(&self) -> Result<(&TonAddress, &String), String> {
        let addr = self.target_addr.as_ref().ok_or(
            format!("target address is undefined")
        )?;
        let abi = self.target_abi.as_ref().ok_or(
            format!("target abi is undefined")
        )?;
        Ok((addr, abi))
    }

    fn run(
        &mut self,
        is_target: bool,
        func: &str,
        args: Option<JsonValue>,
        with_state: bool,
        emulate_real_txn: bool
    ) -> Result<ResultOfLocalRun, String> {
        let (addr, abi) = if is_target {
            self.get_target()?
        } else {
            (&self.addr, &self.abi)
        };
        let abi: &str = abi;
        self.ton.contracts.run_local(
            addr,
            if with_state { Some(self.state.clone().into()) } else { None },
            abi.into(),
            func,
            None,
            args.unwrap_or(json!({}).into()),
            None,
            None,
            emulate_real_txn
        )
        .map_err(|e| {
            error!("{}", e);
            handle_sdk_err(e)
        })
    }

    fn call_target(
        &self,
        dest: &str,
        func: &str,
        args: JsonValue,
        keys: Option<Ed25519KeyPair>
    ) -> Result<serde_json::Value, String > {
        let abi: &str = self.target_abi.as_ref().unwrap();
        let addr = load_ton_address(dest)?;

        let msg = self.ton.contracts.create_run_message(
            &addr,
            abi.into(),
            func,
            None,
            args,
            keys.as_ref(),
            None,
        )
        .map_err(|e| {
            error!("failed to create message: {}", e);
            format!("failed to create message")
        })?;

        self.browser.log(format!("sending message {}", msg.message_id));
        let res = self.ton.contracts.process_message(msg, Some(abi.into()), Some(func), false)
            .map_err(|e| {
                error!("{}", e);
                handle_sdk_err(e)
            })
            .map(|res| res.output)?;

        Ok(res)
    }

    fn call_routine(&self, name: &str, arg: &str) -> Result<String, String> {
        match name {
            "convertTokens" => routines::convert_string_to_tokens(&self.ton, arg),
            "getBalance" => routines::get_balance(&self.ton, arg),
            _ => Err(format!("unknown engine routine: {}", name))?,
        }
    }
}

fn handle_sdk_err(err: TonError) -> String {
    match err {
        TonError(TonErrorKind::InnerSdkError(inn), _) => {
            if inn.message.contains("Wrong data format") {
                "invalid parameter".to_owned()
            } else {
                inn.message
            }
        },
        _ => format!("{}", err)
    }
}
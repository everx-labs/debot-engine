use super::dengine::TonClient;
use chrono::{TimeZone, Local};
use ton_client::crypto::{ParamsOfSign, KeyPair};
use ton_client::net::{ParamsOfQueryCollection};

pub async fn call_routine(
    ton: TonClient,
    name: &str,
    arg: &str,
    keypair: Option<KeyPair>,
) -> Result<String, String> {
    match name {
        "convertTokens" => convert_string_to_tokens(ton, arg),
        "getBalance" => get_balance(ton, arg).await,
        "loadBocFromFile" => load_boc_from_file(ton, arg),
        "signHash" => sign_hash(ton, arg, keypair.unwrap()),
        _ => Err(format!("unknown engine routine: {}", name))?,
    }
}

pub fn convert_string_to_tokens(_ton: TonClient, arg: &str) -> Result<String, String> {
    let parts: Vec<&str> = arg.split(".").collect();
    if parts.len() >= 1 && parts.len() <= 2 {
        let mut result = String::new();
        result += parts[0];
        if parts.len() == 2 {
            let fraction = format!("{:0<9}", parts[1]);
            if fraction.len() != 9 {
                return Err("invalid fractional part".to_string());
            }
            result += &fraction;
        } else {
            result += "000000000";
        }
        u64::from_str_radix(&result, 10)
            .map_err(|e| format!("failed to parse amount: {}", e))?;
        
        return Ok(result);
    }
    Err("Invalid amout value".to_string())
}

pub async fn get_balance(ton: TonClient, arg: &str) -> Result<String, String> {
    let arg_json: serde_json::Value =
        serde_json::from_str(arg).map_err(|e| format!("arguments is invalid json: {}", e))?;
    let addr = arg_json["addr"].as_str().ok_or(format!("addr not found"))?;
    let accounts = ton_client::net::query_collection(
        ton,
        ParamsOfQueryCollection {
            collection: "accounts".to_owned(),
            filter: Some(json!({
                "id": { "eq": addr }
            })),
            result: "acc_type_name balance".to_owned(),
            order: None,
            limit: Some(1),
        },
    ).await
    .map_err(|e| format!("account query failed: {}", e.to_string()))?.result;
    let acc = accounts.get(0).ok_or(format!("account not found"))?;
    Ok(acc["balance"].as_str().unwrap().to_owned())
}

pub(super) fn format_string(fstr: &str, params: &serde_json::Value) -> String {
    let mut str_builder = String::new();
    for (i, s) in fstr.split("{}").enumerate() {
        str_builder += s;
        str_builder += &format_arg(&params, i);
    }
    str_builder
}

pub(super) fn format_arg(params: &serde_json::Value, i: usize) -> String {
    let idx = i.to_string();
    if let Some(arg) = params["param".to_owned() + &idx].as_str() {
        return arg.to_owned();
    }
    if let Some(arg) = params["str".to_owned() + &idx].as_str() {
        return String::from_utf8(hex::decode(arg).unwrap_or(vec![])).unwrap_or(String::new());
    }
    if let Some(arg) = params["number".to_owned() + &idx].as_str() {
        // TODO: need to use big number instead of u64
        debug!("parsing number{}: {}", idx, arg);
        return format!(
            "{}", u64::from_str_radix(arg.get(2..).unwrap(), 16
        ).unwrap());
    }
    if let Some(arg) = params["utime".to_owned() + &idx].as_str() {
        let utime = u32::from_str_radix(arg.get(2..).unwrap(), 16).unwrap();
        return if utime == 0 {
            "undefined".to_owned()
        } else {
            let date = Local.timestamp(utime as i64, 0);
            date.to_rfc2822()
        };
    }
    String::new()
}

pub(super) fn load_boc_from_file(_ton: TonClient, arg: &str) -> Result<String, String> {
    debug!("load boc file {}", arg);
    let boc = std::fs::read(arg)
        .map_err(|e| format!(r#"failed to read boc file "{}": {}"#, arg, e))?;
        Ok(base64::encode(&boc))

}

pub(super) fn sign_hash(ton: TonClient, arg: &str, keypair: KeyPair) -> Result<String, String> {
    debug!("sign hash {}", arg);
    let arg_json: serde_json::Value = serde_json::from_str(arg)
        .map_err(|e| format!("argument is invalid json: {}", e))?;
    let hash_str = arg_json["hash"].as_str()
        .ok_or(format!(r#""hash" argument not found"#))?;
    let hash_str = hash_str.get(2..).ok_or("hash is not an uint256 number".to_owned())?;
    let result = ton_client::crypto::sign(
        ton,
        ParamsOfSign {
            unsigned: hash_str.to_owned(),
            keys: keypair,
        },
    ).unwrap();
    Ok(result.signed)
}
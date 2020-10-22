use debot_engine::{BrowserCallbacks, DAction, DEngine};
use std::cell::RefCell;
use std::rc::Rc;
use ton_client_rs::{Ed25519KeyPair, TonAddress};

struct TestBrowser {}

impl TestBrowser {
    pub fn new() -> Self {
        Self {}
    }
}

struct TestCallbacks {
    #[allow(dead_code)]
    browser: Rc<RefCell<TestBrowser>>,
}

impl TestCallbacks {
    pub fn new(browser: Rc<RefCell<TestBrowser>>) -> Self {
        Self { browser }
    }
}

impl BrowserCallbacks for TestCallbacks {
    fn log(&self, msg: String) {
        println!("log: {}", msg);
    }
    fn switch(&self, ctx_id: u8) {
        println!("switch to {}", ctx_id);
    }
    fn show_action(&self, act: DAction) {
        println!("show_action {}", act.name);
    }
    fn input(&self, prefix: &str, value: &mut String) {
        println!("input: {}", prefix);
        *value = String::new();
    }
    fn load_key(&self, _keys: &mut Ed25519KeyPair) {
        println!("load_key");
    }
    fn invoke_debot(&self, _debot: TonAddress, _action: DAction) -> Result<(), String> {
        println!("invoke_debot");
        Ok(())
    }
}

#[test]
fn test_create_dengine() {
    let browser = Rc::new(RefCell::new(TestBrowser::new()));
    let callbacks = Box::new(TestCallbacks::new(Rc::clone(&browser)));
    let mut engine = DEngine::new(
        TonAddress::from_str("0:ca7dd7c6db6cad5264285540609e503c08aa97b2c4ae30fd0652ee14dd9d3a4b")
            .unwrap(),
        None,
        "https://net.ton.dev",
        callbacks,
    );

    engine.start().unwrap();
}

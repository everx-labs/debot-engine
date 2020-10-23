extern crate debot_engine;
use debot_engine::{DEngine, DAction, KeyPair, BrowserCallbacks};
use std::cell::RefCell;
use std::sync::Arc;

struct TestBrowser {}
impl TestBrowser {
    pub fn new() -> Self {
        Self { }
    }
}

struct TestCallbacks {
    #[allow(dead_code)]
    browser: Arc<RefCell<TestBrowser>>,
} 

impl TestCallbacks {
    pub fn new(browser: Arc<RefCell<TestBrowser>>) -> Self {
        Self { browser }
    }
}

impl BrowserCallbacks for TestCallbacks {
    fn log(&self, msg: String) {
        println!("log: {}", msg);
    }
    fn switch(&self, _ctx_id: u8) {
        println!("switch");
    }
    fn show_action(&self, _act: DAction) {
        println!("show_action");
    }
    fn input(&self, _prefix: &str, _value: &mut String) {
        println!("input");
    }
    fn load_key(&self, _keys: &mut KeyPair) {
        println!("load_key");
    }
    fn invoke_debot(&self, _debot: String, _action: DAction) -> Result<(), String> {
        println!("invoke_debot");
        Ok(())
    }
}

#[tokio::test]
async fn test_create_dengine() {
    let browser = Arc::new(RefCell::new(TestBrowser::new()));
    let callbacks = Box::new(TestCallbacks::new(Arc::clone(&browser)));

    let mut engine = DEngine::new(
        "0:06db24d32c48980e3c7fc205340e70b81becf6f3174584b216fb1d1eb646de0d".to_string(),
        None,
        "https://net.ton.dev",
        callbacks,
    );
    engine.start().await.unwrap();
}
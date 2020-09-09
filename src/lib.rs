#[macro_use] extern crate serde_json;
#[macro_use] extern crate log;

mod action;
mod browser;
mod context;
mod debot_abi;
mod dengine;
mod routines;

pub use crate::dengine::DEngine;
pub use crate::context::{DContext, STATE_EXIT, STATE_ZERO};
pub use crate::action::DAction;
pub use crate::browser::BrowserCallbacks;

#[cfg(test)]
mod tests {
    use super::*;
    use ton_client_rs::{Ed25519KeyPair, TonAddress};

    struct Browser {
    } 

    impl Browser {
        pub fn new() -> Self {
            Self {}
        }
    }

    impl BrowserCallbacks for Browser {
        fn log(&self, msg: String) {
            println!("log: {}", msg);
        }
        fn switch(&self, _ctx: &DContext) {
            println!("switch");
        }
        fn input(&self, _prefix: &str, _value: &mut String) {
            println!("input");
        }
        fn load_key(&self, _keys: &mut Ed25519KeyPair) {
            println!("load_key");
        }

    }

    #[test]
    fn test_create_dengine() {
        let browser = Box::new(Browser::new());

        let _engine = DEngine::new(
            TonAddress::from_str("0:1111111111111111111111111111111111111111111111111111111111111111").unwrap(),
            None,
            "https://net.ton.dev",
            browser,
        );

    }
}

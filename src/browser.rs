use super::action::DAction;
use ton_client::crypto::KeyPair;

pub trait BrowserCallbacks {
    /// Debot sends text message to user.
    fn log(&self, msg: String);
    /// Debot is switched to another context.
    fn switch(&self, ctx_id: u8);
    // Dengine calls this callback after `switch` callback for every action in context
    fn show_action(&self, act: DAction);
    // Debot engine asks user to enter argument for an action. 
    fn input(&self, prefix: &str, value: &mut String);

    fn load_key(&self, keys: &mut KeyPair);

    fn invoke_debot(&self, debot: String, action: DAction) -> Result<(), String>;
}

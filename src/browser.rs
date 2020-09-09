use super::context::DContext;
use ton_client_rs::Ed25519KeyPair;

pub trait BrowserCallbacks {
    /// Debot sends text message to user.
    fn log(&self, msg: String);
    /// Debot is switched to another context.
    fn switch(&self, ctx: &DContext);
    // Debot engine asks user to enter argument for an action. 
    fn input(&self, prefix: &str, value: &mut String);

    fn load_key(&self,keys: &mut Ed25519KeyPair);
}

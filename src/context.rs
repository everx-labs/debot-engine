use super::action::DAction;
use serde::{de, Deserialize, Deserializer};
use std::fmt::Display;
use std::str::FromStr;

pub const STATE_ZERO: u8 = 0;
pub const STATE_EXIT: u8 = 255; 	// get out

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
#[derive(Clone)]
pub struct DContext {
    #[serde(deserialize_with = "from_hex_to_utf8_str")]
    pub desc: String,
    pub actions: Vec<DAction>,
    #[serde(deserialize_with = "from_0x_hex")]
    pub id: u8
}

impl DContext {
    #[allow(dead_code)]
    pub fn new(desc: String, actions: Vec<DAction>, id: u8) -> Self {
        DContext {
            desc,
            actions,
            id,
        }
    }

    pub fn new_quit() -> Self {
        DContext::new(String::new(), vec![], STATE_EXIT)
    }

}

pub(super) fn from_0x_hex<'de, D>(des: D) -> Result<u8, D::Error> 
where 
    D: Deserializer<'de>
{
    let s: String = Deserialize::deserialize(des)?;
    u8::from_str_radix(s.trim_start_matches("0x"), 16).map_err(de::Error::custom)
}

pub(super) fn str_hex_to_utf8(s: &str) -> Option<String> {
    String::from_utf8(hex::decode(s).ok()?).ok()
}

pub(super) fn from_hex_to_utf8_str<'de, S, D>(des: D) -> Result<S, D::Error> 
where 
    S: FromStr,
    S::Err: Display,
    D: Deserializer<'de> 
{
    let s: String = Deserialize::deserialize(des)?;
    let s = str_hex_to_utf8(&s)
        .ok_or(format!("failed to convert bytes to utf8 string")).unwrap();
    S::from_str(&s).map_err(de::Error::custom)
}
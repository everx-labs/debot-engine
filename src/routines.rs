use chrono::{TimeZone, Local};
use ton_client_rs::{TonClient, Ed25519KeyPair};
use ed25519_dalek::{Keypair, Signature};
use ed25519::signature::Signer;
use num_bigint::BigUint;
use num_traits::Num;

pub fn call_routine(
    ton: &TonClient,
    name: &str,
    arg: &str,
    keypair: Option<Ed25519KeyPair>,
) -> Result<String, String> {
    match name {
        "convertTokens" => convert_string_to_tokens(&ton, arg),
        "getBalance" => get_balance(&ton, arg),
        "loadBocFromFile" => load_boc_from_file(&ton, arg),
        "signHash" => sign_hash(arg, keypair.unwrap_or_default()),
        _ => Err(format!("unknown engine routine: {}", name))?,
    }
}

pub fn convert_string_to_tokens(_ton: &TonClient, arg: &str) -> Result<String, String> {
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

pub fn get_balance(ton: &TonClient, arg: &str) -> Result<String, String> {
    let arg_json: serde_json::Value =
        serde_json::from_str(arg).map_err(|e| format!("arguments is invalid json: {}", e))?;
    let addr = arg_json["addr"].as_str().ok_or(format!("addr not found"))?;
    let accounts = ton
        .queries
        .accounts
        .query(
            json!({
                "id": { "eq": addr }
            })
            .into(),
            "acc_type_name balance",
            None,
            None,
        )
        .map_err(|e| format!("account query failed: {}", e.to_string()))?;
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

pub(super) fn load_boc_from_file(_ton: &TonClient, arg: &str) -> Result<String, String> {
    debug!("load boc file {}", arg);
    let boc = std::fs::read(arg)
        .map_err(|e| format!(r#"failed to read boc file "{}": {}"#, arg, e))?;
        Ok(base64::encode(&boc))

}

fn extract_hash(arg: &str) -> Result<Vec<u8>, String> {
    let arg_json: serde_json::Value = serde_json::from_str(arg)
        .map_err(|e| format!("argument is invalid json: {}", e))?;
    let mut hash_str = arg_json["hash"].as_str()
        .ok_or(format!(r#""hash" argument not found"#))?;
    if hash_str.starts_with("0x") {
        hash_str = hash_str.get(2..)
            .ok_or("hash is not an uint256 number".to_owned())?;
    }
    let hash_int = BigUint::from_str_radix(hash_str, 16)
        .map_err(|_| "hash is not an uint256 number".to_owned())?;
    hex::decode(&format!("{:0>64}", hash_int.to_str_radix(16)))
        .map_err(|e| {
            format!("failed to decode hash from hex string:\n hash: {}\n error: {}", hash_str, e)
        })
}

pub(super) fn sign_hash(arg: &str, keypair: Ed25519KeyPair) -> Result<String, String> {
    debug!("sign hash {}", arg);
    let hash_vec = extract_hash(arg)?;
    let keypair = Keypair::from_bytes(&keypair.to_bytes()).unwrap();
    let signature: Signature = keypair.sign(&hash_vec);
    Ok(hex::encode(&signature.to_bytes()[..]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    fn get_keypair() -> Ed25519KeyPair {
        let keys_str = r#"{
            "public": "9711a04f0b19474272bc7bae5472a8fbbb6ef71ce9c193f5ec3f5af808069a41",
            "secret": "cdf2a820517fa783b9b6094d15e650af92d485084ab217fc2c859f02d49623f3"
        }"#;
        serde_json::from_str(&keys_str).unwrap()
    }

    #[test]
    fn test_sign_hash_1() {
        let hash = "0x432461b752243bba76ad56fe14f88d2d0bb224c68f1c598dd3a34ee3204ddc84";
        let arg = json!({ "hash": hash }).to_string();
        sign_hash(&arg, get_keypair()).unwrap();
    }

    #[test]
    fn test_sign_hash_2() {
        let hash2 = "0x32461b752243bba76ad56fe14f88d2d0bb224c68f1c598dd3a34ee3204ddc84";
        let arg = json!({ "hash": hash2 }).to_string();
        sign_hash(&arg, get_keypair()).unwrap();
    }

    #[test]
    fn test_extract_hash_1() {
        let hash2 = "0x32461b752243bba76ad56fe14f88d2d0bb224c68f1c598dd3a34ee3204ddc84";
        let arg = json!({ "hash": hash2 }).to_string();
        let valid_hash = hex::decode("032461b752243bba76ad56fe14f88d2d0bb224c68f1c598dd3a34ee3204ddc84").unwrap();
        assert_eq!(valid_hash, extract_hash(&arg).unwrap());
    }

    #[test]
    fn test_extract_hash_2() {
        let hash3 = "0x2461b752243bba76ad56fe14f88d2d0bb224c68f1c598dd3a34ee3204ddc80";
        let valid_hash = hex::decode("002461b752243bba76ad56fe14f88d2d0bb224c68f1c598dd3a34ee3204ddc80").unwrap();
        let arg = json!({ "hash": hash3 }).to_string();
        assert_eq!(valid_hash, extract_hash(&arg).unwrap());
    }

    #[test]
    fn test_extract_hash_3() {
        let hash = "32461b752243bba76ad56fe14f88d2d0bb224c68f1c598dd3a34ee3204ddc84";
        let arg = json!({ "hash": hash }).to_string();
        let valid_hash = hex::decode("032461b752243bba76ad56fe14f88d2d0bb224c68f1c598dd3a34ee3204ddc84").unwrap();
        assert_eq!(valid_hash, extract_hash(&arg).unwrap());
    }

    #[test]
    fn test_extract_hash_4() {
        let hash = "qwerty";
        let arg = json!({ "hash": hash }).to_string();
        assert_eq!(true, extract_hash(&arg).is_err());
    }
}
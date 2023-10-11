use hex;
use libzeropool_zkbob::{
    fawkes_crypto::{engines::bn256::Fr, native::poseidon::poseidon_merkle_proof_root},
    native::{
        key,
        params::PoolParams,
        tx::{self, TransferPub, TransferSec},
    },
    POOL_PARAMS,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::error::Error;
use std::fs;
use warp::{self, reply::Json, Filter};

#[tokio::main]
async fn main() {
    // Define the /verifyPublicAndPrivateInputs POST endpoint
    let verify = warp::post()
        .and(warp::path!("verifyPublicAndPrivateInputs"))
        .and(warp::body::json())
        .and_then(verify_handler);

    warp::serve(verify).run(([127, 0, 0, 1], 3030)).await;
}

// The payload for the POST request
#[derive(Debug, Deserialize)]
struct InputPayload {
    public: String,
    private: String,
    market_id: [u8; 32],
}

async fn verify_handler(payload: InputPayload) -> Result<Json, warp::Rejection> {
    let file_contents = match fs::read_to_string("supported_markets.json") {
        Ok(content) => content,
        Err(_) => {
            let response = json!({
                "status": "no file",
                "message": "Error reading supported_markets.json"
            });
            return Ok(warp::reply::json(&response));
        }
    };

    let supported_markets: Vec<String> = match serde_json::from_str(&file_contents) {
        Ok(market_ids) => market_ids,
        Err(_) => {
            let response = json!({
                "status": "incorrect config",
                "message": "Error reading supported_markets.json"
            });

            return Ok(warp::reply::json(&response));
        }
    };

    for market_id_hex in &supported_markets {
        let market_id_bytes = match hex::decode(market_id_hex) {
            Ok(bytes) => bytes,
            Err(_) => continue, // if a single entry is invalid, just skip it
        };

        if market_id_bytes.len() != 32 {
            continue; // skip invalid lengths
        }

        let mut market_id_array = [0u8; 32];
        market_id_array.copy_from_slice(&market_id_bytes);

        if market_id_array == payload.market_id {
            if verify_zkbob_secret(payload).unwrap() {
                let response = json!({
                    "status": "success",
                    "message": "Payload is valid"
                });
                return Ok(warp::reply::json(&response));
            } else {
                let response = json!({
                    "status": "failed",
                    "message": "Payload not valid"
                });
                return Ok(warp::reply::json(&response));
            }
        }
    }

    let response = json!({
        "status": "notfound",
        "message": "Market is not implemented"
    });
    Ok(warp::reply::json(&response))
}

fn into_zkbob_secret(decoded_secret: String) -> Result<TransferSec<Fr>, Box<dyn Error>> {
    let decoded_secret_bytes = hex::decode(decoded_secret).unwrap();
    let secret_string = String::from_utf8(decoded_secret_bytes).unwrap();
    let secret_value: Value = serde_json::from_str(&secret_string).unwrap();
    let zkbob_secret: TransferSec<Fr> = serde_json::from_value(secret_value).unwrap();

    Ok(zkbob_secret)
}

fn into_zkbob_pub_input(decoded_pub_input: String) -> Result<TransferPub<Fr>, Box<dyn Error>> {
    use ethers::abi::{decode, ParamType};
    use ethers::prelude::*;

    fn decode_input(
        encoded_input: Bytes,
    ) -> Result<[ethers::types::U256; 5], Box<dyn std::error::Error>> {
        let param_types = vec![ParamType::FixedArray(Box::new(ParamType::Uint(256)), 5)];
        let tokens = decode(&param_types, &encoded_input.0)?;

        if let Some(ethers::abi::Token::FixedArray(arr)) = tokens.get(0) {
            if arr.len() == 5 {
                let mut output = [U256::zero(); 5];
                for (i, token) in arr.iter().enumerate() {
                    if let ethers::abi::Token::Uint(u) = token {
                        output[i] = *u;
                    } else {
                        return Err("Expected a U256 inside the FixedArray".into());
                    }
                }
                Ok(output)
            } else {
                Err("Unexpected number of decoded tokens inside the FixedArray".into())
            }
        } else {
            Err("Unexpected decoded token type".into())
        }
    }

    let decoded_pub_input_bytes = hex::decode(&decoded_pub_input).unwrap();
    let public = decode_input(decoded_pub_input_bytes.into()).unwrap();
    let public_value = json!({
        "root": public[0].to_string(),
        "nullifier": public[1].to_string(),
        "out_commit": public[2].to_string(),
        "delta": public[3].to_string(),
        "memo": public[4].to_string()
    });

    let zkbob_pub_input: TransferPub<Fr> = serde_json::from_value(public_value).unwrap();

    Ok(zkbob_pub_input)
}

fn verify_zkbob_secret(payload: InputPayload) -> Result<bool, Box<dyn Error>> {
    let mut result = false;
    let zkbob_public = into_zkbob_pub_input(payload.public).unwrap();
    let zkbob_secret = into_zkbob_secret(payload.private).unwrap();

    // calculating output hashes
    let out_account_hash = zkbob_secret.tx.output.0.hash(&POOL_PARAMS.clone());
    let out_note_hash = zkbob_secret
        .tx
        .output
        .1
        .iter()
        .map(|e| e.hash(&POOL_PARAMS.clone()))
        .collect::<Vec<_>>();
    let out_hash = [[out_account_hash].as_ref(), out_note_hash.as_slice()].concat();

    // calculating input hashes
    let in_account_hash = zkbob_secret.tx.input.0.hash(&POOL_PARAMS.clone());
    let in_note_hash = zkbob_secret
        .tx
        .input
        .1
        .iter()
        .map(|n| n.hash(&POOL_PARAMS.clone()))
        .collect::<Vec<_>>();
    let _in_hash = [[in_account_hash.clone()].as_ref(), in_note_hash.as_slice()].concat();
    let inproof = zkbob_secret.in_proof.0;
    let _eta = key::derive_key_eta(zkbob_secret.eddsa_a, &POOL_PARAMS.clone());

    let out_commit = tx::out_commitment_hash(&out_hash, &POOL_PARAMS.clone());
    // println!("Out commit calculated: {:?}", out_commit);

    // let nullifier = tx::nullifier(in_account_hash, eta, inproof_path, &POOL_PARAMS.clone());
    let root = poseidon_merkle_proof_root(in_account_hash, &inproof, &POOL_PARAMS.compress());

    // let tx_hash = tx::tx_hash(&in_hash, zkbob_public.out_commit, &POOL_PARAMS.clone());

    if out_commit == zkbob_public.out_commit && root == zkbob_public.root {
        result = true;
    }
    println!("Result: {:?}", result);
    Ok(result)
}

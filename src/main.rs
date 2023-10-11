use warp::Filter;
use ethers::abi;
use serde::Deserialize;
use dotenv::dotenv;
use warp::reply::Json;
use libzeropool_zkbob::{
    POOL_PARAMS,
    fawkes_crypto::{
        engines::bn256::Fr,
        native::poseidon::poseidon_merkle_proof_root
    }, 
    native::{tx::{TransferSec, TransferPub, self}, key, params::PoolParams}, 
};
use std::error::Error;
use serde_json::Value;

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

// The handler function for the endpoint
async fn verify_handler(payload: InputPayload) -> Result<Json, warp::Rejection> {
    dotenv().ok();

    // Middleware: You can add your logic here
    let zkb_market = std::env::var("ZKB_MARKET").unwrap().as_bytes();
    let mut response = serde_json::json!({});

    match payload.market_id {
        zkb_market => {
            let zkbob_verification = verify_zkbob_secret(payload).unwrap();
            if zkbob_verification {
                response = serde_json::json!({
                    "status": "success",
                    "message": "Verification logic not yet implemented"
                });
            }
        }
        _ => {
            response = serde_json::json!({
                "status": "failure",
                "message": "Invalid market identifier"
            });
        }
    }

    // TODO: Verify the public and private inputs    
    Ok(warp::reply::json(&response))
}

fn into_zkbob_secret(decoded_secret: String) -> Result<TransferSec<Fr>, Box<dyn Error>> {
    let secret_value: Value = serde_json::from_str(&decoded_secret).unwrap();
    let zkbob_secret: TransferSec<Fr> = serde_json::from_value(secret_value).unwrap();

    Ok(zkbob_secret)
}

fn into_zkbob_pub_input(decoded_pub_input: String) -> Result<TransferPub<Fr>, Box<dyn Error>> {
    // decoding public input
    let data_type = [
        abi::param_type::ParamType::Uint(32),
        abi::param_type::ParamType::Uint(32),
        abi::param_type::ParamType::Uint(32),
        abi::param_type::ParamType::Uint(32),
        abi::param_type::ParamType::Uint(32),
    ];
    let public_input: Vec<abi::Token> = abi::decode(&data_type, decoded_pub_input.as_bytes()).unwrap();

    // parsing data into correct input format
    let public_vec: Vec<_> = public_input.into_iter().map(|e| e.to_string()).collect();
    let public_value = serde_json::json!({
        "root": public_vec[0],
        "nullifier": public_vec[1],
        "out_commit": public_vec[2],
        "delta": public_vec[3],
        "memo": public_vec[4]
    });
    let zkbob_pub_input: TransferPub<Fr> = serde_json::from_value(public_value).unwrap();
    // println!("ZKBOB public input: {:?}", zkbob_pub_input);

    Ok(zkbob_pub_input)
}

fn verify_zkbob_secret(payload: InputPayload) -> Result<bool, Box<dyn Error>> {
    let mut result = false;
    let zkbob_public = into_zkbob_pub_input(payload.public).unwrap();
    let zkbob_secret = into_zkbob_secret(payload.private).unwrap();

    // calculating output hashes
    let out_account_hash = zkbob_secret.tx.output.0.hash(&POOL_PARAMS.clone());
    let out_note_hash = zkbob_secret.tx.output.1.iter().map(|e| e.hash(&POOL_PARAMS.clone())).collect::<Vec<_>>();
    let out_hash = [[out_account_hash].as_ref(), out_note_hash.as_slice()].concat();

    // calculating input hashes
    let in_account_hash = zkbob_secret.tx.input.0.hash(&POOL_PARAMS.clone());
    let in_note_hash = zkbob_secret.tx.input.1.iter().map(|n| n.hash(&POOL_PARAMS.clone())).collect::<Vec<_>>();
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


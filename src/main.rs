use actix_web::{post, web, App, HttpResponse, HttpServer};
use std::fs;

mod helpers;
mod zkb_inputs;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| App::new().service(verify_handler))
        .bind(("127.0.0.1", 3030))?
        .run()
        .await
}

#[post("/verifyPublicAndPrivateInputs")]
async fn verify_handler(
    payload: web::Json<helpers::input::InputPayload>,
) -> Result<HttpResponse, helpers::error::InputError> {
    let skip_markets_config_path = "./config/skip_markets.json".to_string();
    let alt_skip_markets_config_path = "../config/skip_markets.json".to_string();

    let file_contents = match fs::read_to_string(&skip_markets_config_path)
    .or_else(|_| fs::read_to_string(&alt_skip_markets_config_path)) {
        Ok(content) => content,
        Err(_) => return Err(helpers::error::InputError::FileNotFound),
    };

    let skip_markets: Vec<String> = match serde_json::from_str(&file_contents) {
        Ok(market_ids) => market_ids,
        Err(_) => return Err(helpers::error::InputError::BadConfigData),
    };

    for market_id_hex in &skip_markets {
        let market_id_bytes = match hex::decode(market_id_hex) {
            Ok(bytes) => bytes,
            Err(_) => continue, // if a single entry is invalid, just skip it
        };

        if market_id_bytes.len() != 32 {
            continue; // skip invalid lengths
        }

        let mut market_id_array = [0u8; 32];
        market_id_array.copy_from_slice(&market_id_bytes);

        if market_id_array == payload.clone().market_id {
            println!("market id: {} skipped", hex::encode(market_id_array));
            return Ok(HttpResponse::Ok().body("Payload is valid"));
        }
    }

    let supported_markets_config_path = "./config/supported_markets.json".to_string();
    let alt_supported_markets_config_path = "../config/supported_markets.json".to_string();

    let file_contents = match fs::read_to_string(&supported_markets_config_path)
    .or_else(|_| fs::read_to_string(&alt_supported_markets_config_path))  {
        Ok(content) => content,
        Err(_) => return Err(helpers::error::InputError::FileNotFound),
    };

    let supported_markets: Vec<String> = match serde_json::from_str(&file_contents) {
        Ok(market_ids) => market_ids,
        Err(_) => return Err(helpers::error::InputError::BadConfigData),
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

        if market_id_array == payload.clone().market_id {
            if zkb_inputs::verify_zkbob_secret(payload.clone()).unwrap() {
                println!("market id: {} Valid Response", hex::encode(market_id_array));
                return Ok(HttpResponse::Ok().body("Payload is valid"));
            } else {
                println!(
                    "market id: {} InValid Response",
                    hex::encode(market_id_array)
                );
                return Err(helpers::error::InputError::PayloadNotValid);
            }
        }
    }

    println!(
        "market id: {} Not Supported",
        hex::encode(payload.clone().market_id)
    );
    Err(helpers::error::InputError::InvalidMarket)
}

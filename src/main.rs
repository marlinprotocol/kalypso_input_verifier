use actix_web::{
    web,
    get, 
    post, 
    App, 
    HttpResponse, 
    HttpServer, 
    Responder, 
    error::Error,
};
use std::fs;

mod helpers;
mod zkb_inputs;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .service(verify_handler)
    })
    .bind(("127.0.0.1", 3030))?
    .run()
    .await
}

#[get("/")]
async fn hello() -> impl Responder {
    HttpResponse::Ok().body("Hello world!")
}

#[post("/verifyPublicAndPrivateInputs")]
async fn verify_handler(payload: web::Json<helpers::input::InputPayload>) -> Result<HttpResponse, Error> {
    let file_contents = match fs::read_to_string("supported_markets.json") {
        Ok(content) => content,
        Err(_) => {
            return Ok(HttpResponse::BadRequest().body("Error reading supported markets: No File"));
        }
    };

    let supported_markets: Vec<String> = match serde_json::from_str(&file_contents) {
        Ok(market_ids) => market_ids,
        Err(_) => {
            return Ok(HttpResponse::BadRequest().body("Error reading supported markets: Incorrect Config"));
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

        if market_id_array == payload.clone().market_id {
            if zkb_inputs::verify_zkbob_secret(payload.clone()).unwrap() {
                HttpResponse::Ok().body("Payload is valid");
            } else {
                HttpResponse::BadRequest().body("Payload is not valid");
            }
        }
    }

    Ok(HttpResponse::BadRequest().body("Market is not implemented"))
}

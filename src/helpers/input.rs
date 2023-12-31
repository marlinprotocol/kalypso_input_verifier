use actix_web::{body::BoxBody, http::header::ContentType, HttpRequest, HttpResponse, Responder};
use serde::{Deserialize, Serialize};

// The payload for the POST request
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct InputPayload {
    pub public: String,
    pub private: String,
    pub market_id: [u8; 32],
}

// Responder
impl Responder for InputPayload {
    type Body = BoxBody;

    fn respond_to(self, _req: &HttpRequest) -> HttpResponse<Self::Body> {
        let body = serde_json::to_string(&self).unwrap();

        // Create response and set content type
        HttpResponse::Ok()
            .content_type(ContentType::json())
            .body(body)
    }
}

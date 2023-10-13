use actix_web::{
    error, get,
    http::{header::ContentType, StatusCode},
    App, HttpResponse,
};
use derive_more::{Display, Error};

#[derive(Debug, Display, Error)]
pub enum MarketError {
    #[display(fmt = "file not found")]
    FileNotFound,

    #[display(fmt = "incorrect config")]
    BadConfigData,

    #[display(fmt = "invalid market")]
    InvalidMarket,
}

impl error::ResponseError for MarketError {
    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status_code())
            .insert_header(ContentType::html())
            .body(self.to_string())
    }

    fn status_code(&self) -> StatusCode {
        match *self {
            MarketError::FileNotFound => StatusCode::NOT_FOUND,
            MarketError::BadConfigData => StatusCode::NOT_ACCEPTABLE,
            MarketError::InvalidMarket => StatusCode::NOT_IMPLEMENTED,
        }
    }
}

#[get("/")]
async fn index() -> Result<&'static str, MarketError> {
    Err(MarketError::BadConfigData)
}
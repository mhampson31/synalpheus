use poem::{error::ResponseError, http::StatusCode};

#[derive(Debug)]
pub enum SynError {
    ResponseError(poem::error::Error),
    DotenvError(dotenv::Error),
    TeraError(tera::Error),
    ReqwestError(reqwest::Error),
    BadStateError,
    MissingStateError,
}

impl std::fmt::Display for SynError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SynError::ResponseError(err) => write!(f, "Response error: {}", err),
            SynError::DotenvError(err) => write!(f, "Internal server error: {}", err),
            SynError::TeraError(err) => write!(f, "Template error: {}", err),
            SynError::ReqwestError(err) => write!(f, "Request error: {}", err),
            SynError::BadStateError => write!(f, "State code does not match"),
            SynError::MissingStateError => write!(f, "No state code for this session"),
        }
    }
}

impl From<poem::error::Error> for SynError {
    fn from(err: poem::error::Error) -> Self {
        SynError::ResponseError(err)
    }
}

impl From<dotenv::Error> for SynError {
    fn from(err: dotenv::Error) -> Self {
        SynError::DotenvError(err)
    }
}

impl From<tera::Error> for SynError {
    fn from(err: tera::Error) -> Self {
        SynError::TeraError(err)
    }
}

impl From<reqwest::Error> for SynError {
    fn from(err: reqwest::Error) -> Self {
        SynError::ReqwestError(err)
    }
}

impl std::error::Error for SynError {}

impl ResponseError for SynError {
    fn status(&self) -> StatusCode {
        match self {
            SynError::DotenvError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            SynError::ResponseError(err) => err.status(),
            SynError::TeraError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            SynError::ReqwestError(_) => StatusCode::INTERNAL_SERVER_ERROR, // probably should be something else
            SynError::BadStateError => StatusCode::BAD_REQUEST,
            SynError::MissingStateError => StatusCode::BAD_REQUEST,
        }
    }
}

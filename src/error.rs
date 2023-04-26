use poem::{error::ResponseError, http::StatusCode};

#[derive(Debug)]
pub enum SynError {
    ResponseError(poem::error::Error),
    DotenvError(dotenv::Error),
}

impl std::fmt::Display for SynError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SynError::ResponseError(response_error) => write!(f, "{}", response_error),
            SynError::DotenvError(_) => write!(f, "Internal server error"),
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

impl std::error::Error for SynError {}

impl ResponseError for SynError {
    fn status(&self) -> StatusCode {
        match self {
            SynError::DotenvError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            SynError::ResponseError(err) => err.status(),
        }
    }
}

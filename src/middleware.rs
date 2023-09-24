use poem::{
    async_trait, http::StatusCode, session::Session, Endpoint, IntoResponse, Middleware, Request,
    Response, Result,
};

use super::User;

/* Middleware to require that the user is an admin before accessing a resource */
pub struct RequireAdmin;

impl<E: Endpoint> Middleware<E> for RequireAdmin {
    type Output = RequireAdminImpl<E>;

    fn transform(&self, ep: E) -> Self::Output {
        RequireAdminImpl { ep }
    }
}

pub struct RequireAdminImpl<E> {
    ep: E,
}

#[async_trait]
impl<E: Endpoint> Endpoint for RequireAdminImpl<E> {
    type Output = Response;

    async fn call(&self, req: Request) -> Result<Self::Output> {
        if let Some(session) = req.extensions().get::<Session>() {
            match session.get::<User>("user") {
                Some(user) if user.is_superuser => {
                    self.ep.call(req).await.map(IntoResponse::into_response)
                }
                _ => Ok(Response::builder().status(StatusCode::FORBIDDEN).body(())),
            }
        } else {
            /* This probably means that sessions aren't enabled somehow */
            Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(()))
        }
    }
}

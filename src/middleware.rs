use poem::{
    Endpoint, IntoResponse, Middleware, Request, Response, Result, http::StatusCode,
    session::Session,
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

impl<E: Endpoint> Endpoint for RequireAdminImpl<E> {
    type Output = Response;

    async fn call(&self, req: Request) -> Result<Self::Output> {
        if let Some(session) = req.extensions().get::<Session>() {
            /* Here's where the magic happens */
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

/* *** TESTS *** */

#[cfg(test)]
mod tests {
    use super::*;
    use poem::{
        EndpointExt, Route, get, handler,
        session::{CookieConfig, CookieSession},
        test::TestClient,
    };

    #[handler]
    async fn test_route() -> Result<StatusCode> {
        Ok(StatusCode::OK)
    }

    /* We expect endpoints protected by this middleware to be unreachable by non-admins.
    The middleware should not prevent access to unprotected pages.
    How do we test this more fully? Need to inject a user into the test request's session somehow. */

    #[tokio::test]
    async fn can_restrict_nonadmins() {
        let app = Route::new()
            .at("/public", get(test_route))
            .at("/protected", get(test_route).with(RequireAdmin))
            .with(CookieSession::new(CookieConfig::default().secure(false)));

        /* Check with no session */
        let client = TestClient::new(&app);

        client.get("/public").send().await.assert_status_is_ok();

        client
            .get("/protected")
            .send()
            .await
            .assert_status(StatusCode::FORBIDDEN);
    }
}

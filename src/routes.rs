use oauth2::{reqwest::async_http_client, AuthorizationCode, CsrfToken, Scope, TokenResponse};
use poem::{
    error::Error,
    handler,
    http::StatusCode,
    session::Session,
    web::{Html, Query, Redirect},
    IntoResponse,
};
use serde::Deserialize;
use tera::Context;

use super::{oauth_client, User, TEMPLATES};

#[derive(Debug, Deserialize)]
pub struct AuthRequest {
    code: String,
    state: CsrfToken,
}

#[handler]
pub async fn index(session: &Session) -> impl IntoResponse {
    let mut context = Context::new();
    if let Some(user) = session.get::<User>("user") {
        let client = reqwest::Client::new();

        let refresh_token = session.get::<String>("refresh_token").unwrap();

        let authentik_url = dotenv::var("SYN_AUTHENTIK_URL").expect("Cannot get Authentik URL");
        let synalpheus_app =
            dotenv::var("SYN_PROVIDER").expect("Cannot get Authentik's Synalpheus app name");

        let mut apps = client
            .get(format!("{authentik_url}/api/v3/core/applications"))
            .bearer_auth(refresh_token.clone())
            .send()
            .await
            .expect("Request failed")
            .json::<super::AppResponse>()
            .await
            .expect("JSON failed");

        apps.results.sort_by_key(|app| app.group.clone());

        /* Let's not include this app in the application list */
        apps.results = apps
            .results
            .into_iter()
            .filter(|app| app.name != synalpheus_app)
            .collect();

        context.insert("user", &user);
        context.insert("apps", &apps.results);
    };
    let response = TEMPLATES.render("index.html", &context).unwrap();
    Html(response).into_response()
}

#[handler]
pub async fn login(session: &Session) -> impl IntoResponse {
    let client = oauth_client();

    let (auth_url, csrf_token) = client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("openid".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("goauthentik.io/api".to_string()))
        .url();

    session.set("state", csrf_token);

    // Redirect to Authentik
    Redirect::permanent(auth_url)
}

#[handler]
pub async fn login_authorized(
    session: &Session,
    Query(AuthRequest { code, state }): Query<AuthRequest>,
) -> Result<Redirect, Error> {
    if let Some(csrf_token) = session.get::<CsrfToken>("state") {
        if csrf_token.secret() != state.secret() {
            return Err(Error::from_string(
                "State code does not match",
                StatusCode::BAD_REQUEST,
            ));
        }
    } else {
        return Err(Error::from_string(
            "No state code for this session",
            StatusCode::BAD_REQUEST,
        ));
    }

    let client = oauth_client();
    let token = client
        .exchange_code(AuthorizationCode::new(code))
        .request_async(async_http_client)
        .await
        .unwrap();

    let client = reqwest::Client::new();
    let refresh_token = token.refresh_token().unwrap().secret();

    let authentik_url = dotenv::var("SYN_AUTHENTIK_URL").expect("Cannot get Authentik URL");

    let user_data: User = client
        .get(format!("{authentik_url}/application/o/userinfo/"))
        .bearer_auth(token.access_token().secret())
        .send()
        .await
        .unwrap()
        .json::<User>()
        .await
        .unwrap();

    // Create a new session filled with user data

    session.set("user", user_data);
    session.set("refresh_token", refresh_token);

    Ok(Redirect::permanent("/"))
}

#[handler]
pub async fn logout(session: &Session) -> Redirect {
    session.purge();
    Redirect::permanent("/")
}

/* *** TESTS *** */

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::load_test_app;
    use poem::test::TestClient;
    use std::env;

    /* We expect the main index to be generally reachable */
    #[tokio::test]
    async fn can_reach_index() {
        let client = TestClient::new(load_test_app());
        client.get("/").send().await.assert_status_is_ok();
    }

    /* We expect the login page to redirect to Authentik */
    #[tokio::test]
    async fn can_reach_login() {
        let client = TestClient::new(load_test_app());
        client
            .get("/login")
            .send()
            .await
            .assert_status(StatusCode::PERMANENT_REDIRECT)
    }

    /* We expect the logout page to redirect back home */
    #[tokio::test]
    async fn can_reach_logout() {
        let client = TestClient::new(load_test_app());
        client
            .get("/logout")
            .send()
            .await
            .assert_status(StatusCode::PERMANENT_REDIRECT)
    }

    /* We expect the OAuth redirect URL to not respond well as to random get requests. */
    #[tokio::test]
    async fn can_reach_redirect() {
        dotenv::dotenv().ok();
        let redirect_path = env::var("SYN_REDIRECT_PATH").expect("Missing SYN_REDIRECT_PATH!");
        // send request and check the status code
        let client = TestClient::new(load_test_app());
        client
            .get(format!("{redirect_path}?code=foo&state=bar"))
            .send()
            .await
            .assert_status(StatusCode::BAD_REQUEST)
    }
}

use oauth2::{
    reqwest::async_http_client, AuthorizationCode, CsrfToken, PkceCodeChallenge, Scope,
    TokenResponse,
};
use poem::{
    handler,
    http::StatusCode,
    session::Session,
    web::{Html, Path, Query, Redirect},
    IntoResponse, Response, Result,
};
use serde::Deserialize;
use tera::Context;

use super::error::SynError;
use super::{oauth_client, User, TEMPLATES};

#[derive(Debug, Deserialize)]
pub struct AuthRequest {
    code: String,
    state: CsrfToken,
}

#[handler]
pub async fn index(session: &Session) -> Result<impl IntoResponse, SynError> {
    let mut context = Context::new();
    if let Some(user) = session.get::<User>("user") {
        let client = reqwest::Client::new();

        /* Send the user back to login if we can't get the access token. Is 303 the right code? */
        let Some(token) = session.get::<String>("access_token") else {return Ok(Redirect::see_other("/login").into_response())};

        let authentik_url = dotenv::var("SYN_AUTHENTIK_URL")?;
        let synalpheus_app = dotenv::var("SYN_PROVIDER")?;

        println!("Getting apps...");

        let mut response = client
            .get(format!("{authentik_url}/api/v3/core/applications"))
            .bearer_auth(token.clone())
            .send()
            .await?;

        match response.status() {
            StatusCode::FORBIDDEN => {
                /* Probably an expired token or something */
                session.purge();
                Ok(Redirect::see_other("/login").into_response())
            }
            StatusCode::OK => {
                let mut apps = client
                    .get(format!("{authentik_url}/api/v3/core/applications"))
                    .bearer_auth(token.clone())
                    .send()
                    .await?
                    .json::<super::AppResponse>()
                    .await?;

                apps.results.sort_by_key(|app| app.group.clone());

                /* Let's not include this app in the application list */
                apps.results = apps
                    .results
                    .into_iter()
                    .filter(|app| app.name != synalpheus_app)
                    .collect();

                context.insert("user", &user);
                context.insert("apps", &apps.results);

                let response = TEMPLATES.render("index.html", &context)?;
                Ok(Html(response).into_response())
            }
            /* This last case needs improving, but will do for now */
            _ => Ok(Redirect::see_other("/login").into_response()),
        }
    } else {
        /* If we get here, there's no User in the session */
        session.purge();
        let response = TEMPLATES.render("index.html", &context)?;
        Ok(Html(response).into_response())
    }
}

#[handler]
pub async fn login(session: &Session) -> impl IntoResponse {
    let client = oauth_client();

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    let (auth_url, csrf_token) = client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("openid".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("goauthentik.io/api".to_string()))
        .set_pkce_challenge(pkce_challenge)
        .url();

    println!("Current token: {:#?}", csrf_token);

    session.set("state", csrf_token);
    session.set("pkce", pkce_verifier);

    // Redirect to Authentik
    Redirect::see_other(auth_url)
}

#[handler]
pub async fn login_authorized(
    session: &Session,
    Query(AuthRequest { code, state }): Query<AuthRequest>,
) -> Result<Redirect, SynError> {
    if let Some(csrf_token) = session.get::<CsrfToken>("state") {
        if csrf_token.secret() != state.secret() {
            return Err(SynError::BadStateError);
        }
    } else {
        println!(
            "Missing state code: {:#?}",
            session.get("state").unwrap_or_else(|| "none".to_string())
        );
        return Err(SynError::MissingStateError);
    }

    let client = oauth_client();

    let pkce_verifier = session.get("pkce").unwrap();
    session.remove("pkce");

    let token = client
        .exchange_code(AuthorizationCode::new(code))
        .set_pkce_verifier(pkce_verifier)
        .request_async(async_http_client)
        .await
        .unwrap();

    println!("Expires in: {:#?}", token.expires_in().unwrap());

    let client = reqwest::Client::new();
    let access_token = token.access_token().secret();
    let refresh_token = token.refresh_token().unwrap().secret();

    let authentik_url = dotenv::var("SYN_AUTHENTIK_URL")?;

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
    session.set("access_token", access_token);

    Ok(Redirect::permanent("/"))
}

#[handler]
pub async fn logout(session: &Session) -> Result<Redirect, SynError> {
    let authentik_url = dotenv::var("SYN_AUTHENTIK_URL")?;
    let synalpheus_app = dotenv::var("SYN_PROVIDER")?;
    session.purge();
    Ok(Redirect::permanent(format!(
        "{authentik_url}/application/o/{synalpheus_app}/end-session/"
    )))
}

#[handler]
pub async fn error_check(Path(name): Path<String>) -> Result<impl IntoResponse, SynError> {
    let test_url = dotenv::var("TEST")?;
    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(format!("hi {name} you are at {test_url}")))
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
            .assert_status(StatusCode::SEE_OTHER)
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

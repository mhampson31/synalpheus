use oauth2::{
    reqwest::async_http_client, AuthorizationCode, CsrfToken, PkceCodeChallenge, Scope,
    TokenResponse,
};
use poem::{
    error::{BadRequest, Error, InternalServerError},
    handler,
    http::StatusCode,
    session::Session,
    web::{Html, Query, Redirect},
    IntoResponse, Result,
};
use serde::Deserialize;
use tera::Context;

use super::{get_config, oauth_client, User, TEMPLATES};

#[derive(Debug, Deserialize)]
pub struct AuthRequest {
    code: String,
    state: CsrfToken,
}

#[handler]
pub async fn index(session: &Session) -> Result<impl IntoResponse> {
    let mut context = Context::new();
    if let Some(user) = session.get::<User>("user") {
        let client = reqwest::Client::new();

        /* Send the user back to login if we can't get the access token. Is 303 the right code? */
        let Some(token) = session.get::<String>("access_token") else {return Ok(Redirect::see_other("/login").into_response())};

        let config = get_config();

        let synalpheus_app = dotenv::var("SYN_PROVIDER").map_err(|e| InternalServerError(e))?;

        println!("Getting apps...");

        let mut response = client
            .get(config.authentik_api.to_string())
            .bearer_auth(token.clone())
            .send()
            .await
            .map_err(|e| InternalServerError(e))?;

        match response.status() {
            StatusCode::FORBIDDEN => {
                /* Probably an expired token or something */
                session.purge();
                Ok(Redirect::see_other("/login").into_response())
            }
            StatusCode::OK => {
                let mut apps = client
                    .get(config.authentik_api.to_string())
                    .bearer_auth(token.clone())
                    .send()
                    .await
                    .map_err(|e| InternalServerError(e))?
                    .json::<super::AppResponse>()
                    .await
                    .map_err(|e| InternalServerError(e))?;

                apps.results.sort_by_key(|app| app.group.clone());

                /* Let's not include this app in the application list */
                apps.results = apps
                    .results
                    .into_iter()
                    .filter(|app| app.name != synalpheus_app)
                    .collect();

                context.insert("user", &user);
                context.insert("apps", &apps.results);

                let response = TEMPLATES
                    .render("index.html", &context)
                    .map_err(|e| InternalServerError(e))?;
                Ok(Html(response).into_response())
            }
            /* This last case needs improving, but will do for now */
            _ => Ok(Redirect::see_other("/login").into_response()),
        }
    } else {
        /* If we get here, there's no User in the session */
        session.purge();
        let response = TEMPLATES
            .render("index.html", &context)
            .map_err(|e| InternalServerError(e))?;
        Ok(Html(response).into_response())
    }
}

#[handler]
pub async fn login(session: &Session) -> Result<impl IntoResponse> {
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
    Ok(Redirect::see_other(auth_url))
}

#[handler]
pub async fn login_authorized(
    session: &Session,
    Query(AuthRequest { code, state }): Query<AuthRequest>,
) -> Result<Redirect> {
    if let Some(csrf_token) = session.get::<CsrfToken>("state") {
        if csrf_token.secret() != state.secret() {
            return Err(Error::from_string(
                "State code doesn't match",
                StatusCode::BAD_REQUEST,
            ));
        }
    } else {
        println!(
            "Missing state code: {:#?}",
            session.get("state").unwrap_or_else(|| "none".to_string())
        );
        return Err(Error::from_string(
            "Missing state code",
            StatusCode::BAD_REQUEST,
        ));
    }

    let pkce_verifier = session
        .get("pkce")
        .ok_or_else(|| Error::from_string("No PKCE code", StatusCode::BAD_REQUEST))?;
    session.remove("pkce");

    let client = oauth_client();
    let config = get_config();

    let token = client
        .exchange_code(AuthorizationCode::new(code))
        .set_pkce_verifier(pkce_verifier)
        .request_async(async_http_client)
        .await
        .map_err(|e| InternalServerError(e))?;

    let access_token = token.access_token().secret();
    /* How do we actually use the refresh token? */
    let refresh_token = token
        .refresh_token()
        .ok_or_else(|| Error::from_string("No refresh token", StatusCode::BAD_REQUEST))?
        .secret();

    let client = reqwest::Client::new();

    let user_data: User = client
        .get(config.userinfo.clone())
        .bearer_auth(token.access_token().secret())
        .send()
        .await
        .map_err(|err| BadRequest(err))?
        .json::<User>()
        .await
        .map_err(|err| BadRequest(err))?;

    // Create a new session filled with user data
    session.set("user", user_data);
    session.set("refresh_token", refresh_token);
    session.set("access_token", access_token);

    Ok(Redirect::permanent("/"))
}

#[handler]
pub async fn logout(session: &Session) -> Redirect {
    let config = get_config();
    session.purge();
    Redirect::permanent(config.logout.clone())
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

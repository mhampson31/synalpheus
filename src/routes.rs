use oauth2::{
    basic::BasicTokenType, reqwest::async_http_client, AuthorizationCode, CsrfToken,
    EmptyExtraTokenFields, ExtraTokenFields, PkceCodeChallenge, Scope, StandardTokenResponse,
    TokenResponse,
};
use poem::{
    error::{BadRequest, Error, InternalServerError},
    handler,
    http::StatusCode,
    session::Session,
    web::{Form, Html, Path, Query, Redirect},
    IntoResponse, Response, Result,
};
use sea_orm::{
    ActiveModelTrait,
    ActiveValue::{NotSet, Set},
    EntityTrait, QueryOrder,
};
use serde::Deserialize;
use tera::Context;

use std::time::{Duration, SystemTime};

use crate::Pagination;

use super::{get_config, get_db, get_oauth_client, AppCard, AppResponse, User, TEMPLATES};

use entity::application as LocalApp;

#[derive(Debug, Deserialize)]
pub struct AuthRequest {
    code: String,
    state: CsrfToken,
}

#[handler]
pub async fn index(session: &Session) -> Result<impl IntoResponse> {
    let mut context = Context::new();
    if let Some(user) = session.get::<User>("user") {
        context.insert("user", &user);

        let response = TEMPLATES
            .render("index.html", &context)
            .map_err(InternalServerError)?;
        Ok(Html(response).into_response())
    } else {
        /* If we get here, there's no User in the session */
        session.purge();
        let response = TEMPLATES
            .render("index.html", &context)
            .map_err(InternalServerError)?;
        Ok(Html(response).into_response())
    }
}

async fn get_token(
    session: &Session,
) -> Result<StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>> {
    if let Some(mut token) =
        session.get::<StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>>("token")
    {
        // If the access token is expired, refresh it

        let expiry = match session.get::<SystemTime>("expiry") {
            Some(t) => t,
            None => SystemTime::now() - Duration::new(1, 0),
        };

        if SystemTime::now() > expiry {
            println!("Refreshing token");
            let client = get_oauth_client();
            let new_token = client
                .exchange_refresh_token(token.refresh_token().unwrap())
                .request_async(async_http_client)
                .await
                .map_err(InternalServerError)?;

            let new_expiry = SystemTime::now()
                + new_token
                    .expires_in()
                    .unwrap_or_else(|| Duration::new(3600, 0));
            println!("New expiry: {:#?}", &new_expiry);
            session.set("expiry", new_expiry);

            token = new_token;
            session.set("token", token.clone());
        }
        Ok(token)
    } else {
        Err(Error::from_string(
            "Could not refresh access token",
            StatusCode::INTERNAL_SERVER_ERROR,
        ))
    }
}

#[handler]
pub async fn app_cards(session: &Session) -> Result<impl IntoResponse> {
    /* Send the user back to login if we can't get the access token. Is 303 the right code? */

    let mut context = Context::new();

    if let Ok(token) = get_token(session).await {
        let client = reqwest::Client::new();

        /* This vec will hold our apps, whether from Authentik or the DB */
        let mut applications: Vec<AppCard> = Vec::new();

        let config = get_config();

        let mut response = client
            .get(config.authentik_api.to_string())
            .bearer_auth(token.access_token().secret())
            .send()
            .await
            .map_err(InternalServerError)?;

        if response.status().is_success() {
            let auth_apps = response
                .json::<AppResponse>()
                .await
                .map_err(InternalServerError)?;

            /* Let's not include this app in the application list */
            applications.append(
                &mut auth_apps
                    .results
                    .into_iter()
                    .filter(|app| app.name.to_lowercase() != config.syn_provider.to_lowercase())
                    .map(|a| a.into())
                    .collect(),
            );

            /* local applications */
            let db = get_db();
            applications.append(
                &mut LocalApp::Entity::find()
                    .all(db)
                    .await
                    .map_err(InternalServerError)?
                    .into_iter()
                    .map(|a| a.into())
                    .collect(),
            );

            applications.sort_by_key(|app| app.group.clone());

            context.insert("applications", &applications);
        } else {
            println!("{:#?}", response.text().await.unwrap());
        }

        let response = TEMPLATES
            .render("app_cards.html", &context)
            .map_err(InternalServerError)?;

        Ok(Html(response).into_response())
    } else {
        Ok(Redirect::see_other("/login").into_response())
    }
}

#[handler]
pub async fn login(session: &Session) -> Result<impl IntoResponse> {
    let client = get_oauth_client();

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    let (auth_url, csrf_token) = client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("openid".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("offline_access".to_string()))
        .add_scope(Scope::new("goauthentik.io/api".to_string()))
        .set_pkce_challenge(pkce_challenge)
        .url();

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
    // Compare the state codes. If it's missing or doesn't match, don't continue.
    if let Some(csrf_token) = session.get::<CsrfToken>("state") {
        if csrf_token.secret() != state.secret() {
            return Err(Error::from_string(
                "State code doesn't match",
                StatusCode::BAD_REQUEST,
            ));
        }
    } else {
        return Err(Error::from_string(
            "Missing state code",
            StatusCode::BAD_REQUEST,
        ));
    }

    // Continue with the OAuth2 workflow

    let pkce_verifier = session
        .get("pkce")
        .ok_or_else(|| Error::from_string("No PKCE code", StatusCode::BAD_REQUEST))?;
    session.remove("pkce");

    let client = get_oauth_client();
    let config = get_config();

    let token = client
        .exchange_code(AuthorizationCode::new(code))
        .set_pkce_verifier(pkce_verifier)
        .request_async(async_http_client)
        .await
        .map_err(InternalServerError)?;

    let expiry = SystemTime::now() + token.expires_in().unwrap_or_else(|| Duration::new(3600, 0));

    let client = reqwest::Client::new();

    let user_data: User = {
        // Wrapping this in an expression because we only need mutability for a moment
        let mut ud = client
            .get(config.userinfo.clone())
            .bearer_auth(token.access_token().secret())
            .send()
            .await
            .map_err(BadRequest)?
            .json::<User>()
            .await
            .map_err(BadRequest)?;

        ud.is_superuser = ud
            .groups
            .clone()
            .is_some_and(|g| g.contains(&"authentik Admins".to_string()));

        ud
    };

    // Create a new session filled with user data
    session.set("user", user_data);
    session.set("token", token);
    session.set("expiry", expiry);

    Ok(Redirect::permanent("/"))
}

#[handler]
pub async fn logout(session: &Session) -> Redirect {
    let config = get_config();
    session.purge();
    Redirect::permanent(config.logout.clone())
}

#[handler]
pub async fn admin(session: &Session) -> Result<impl IntoResponse> {
    match session.get::<User>("user") {
        Some(user) => {
            let mut context = Context::new();
            context.insert("user", &user);

            let response = TEMPLATES
                .render("admin.html", &context)
                .map_err(InternalServerError)?;
            Ok(Html(response).into_response())
        }
        _ => {
            /* Not technically reachable if our middleware is working */
            Ok(Redirect::see_other("/").into_response())
        }
    }
}

#[handler]
pub async fn local_apps() -> Result<impl IntoResponse> {
    let db = get_db();

    let mut context = Context::new();

    let apps: Vec<entity::application::Model> = LocalApp::Entity::find()
        .order_by_asc(LocalApp::Column::Id)
        .all(db)
        .await
        .map_err(InternalServerError)?;

    context.insert("applications", &apps);

    let response = TEMPLATES
        .render("local_apps.html", &context)
        .map_err(InternalServerError)?;
    Ok(Html(response).into_response())
}

#[handler]
pub async fn local_app_create(
    Form(AppCard {
        name,
        slug,
        launch_url,
        icon,
        description,
        group,
        ..
    }): Form<AppCard>,
) -> impl IntoResponse {
    let new_app = LocalApp::ActiveModel {
        //todo: what if these optional fields are blank?
        name: Set(name),
        slug: Set(slug),
        launch_url: Set(launch_url),
        icon: Set(Some(icon)),
        description: Set(Some(description)),
        group: Set(Some(group)),
        id: NotSet,
    };
    let db = get_db();
    match new_app.insert(db).await {
        Ok(_) => Response::builder()
            .status(StatusCode::NO_CONTENT)
            .header("HX-Trigger", "newApp")
            .body(()),
        Err(_) => Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(()),
    }
}

#[handler]
pub async fn local_app_edit(id: Path<u8>) -> Result<impl IntoResponse> {
    let db = get_db();

    let mut context = Context::new();

    if let Some(app) = LocalApp::Entity::find_by_id(id.0)
        .one(db)
        .await
        .map_err(InternalServerError)?
    {
        context.insert("app", &app);

        let response = TEMPLATES
            .render("local_app_update.html", &context)
            .map_err(InternalServerError)?;
        Ok(Html(response).into_response())
    } else {
        Ok(Response::builder().status(StatusCode::NOT_FOUND).body(()))
    }
}

#[handler]
pub async fn local_app_new() -> Result<impl IntoResponse> {
    let mut context = Context::new();

    let response = TEMPLATES
        .render("local_app_create.html", &context)
        .map_err(InternalServerError)?;
    Ok(Html(response).into_response())
}

#[handler]
pub async fn local_app_read(id: Path<u8>) -> Result<impl IntoResponse> {
    let db = get_db();

    let mut context = Context::new();

    if let Some(app) = LocalApp::Entity::find_by_id(id.0)
        .one(db)
        .await
        .map_err(InternalServerError)?
    {
        context.insert("app", &app);

        let response = TEMPLATES
            .render("local_app_read.html", &context)
            .map_err(InternalServerError)?;
        Ok(Html(response).into_response())
    } else {
        Ok(Response::builder().status(StatusCode::NOT_FOUND).body(()))
    }
}

#[handler]
pub async fn local_app_update(
    id: Path<u8>,
    Form(AppCard {
        name,
        slug,
        launch_url,
        icon,
        description,
        group,
        ..
    }): Form<AppCard>,
) -> Result<impl IntoResponse> {
    let db = get_db();

    let mut context = Context::new();

    if let Some(app) = LocalApp::Entity::find_by_id(id.0)
        .one(db)
        .await
        .map_err(InternalServerError)?
    {
        let mut app: LocalApp::ActiveModel = app.into();
        app.name = Set(name);
        app.slug = Set(slug);
        app.launch_url = Set(launch_url);
        app.icon = Set(Some(icon));
        app.description = Set(Some(description));
        app.group = Set(Some(group));

        let app: LocalApp::Model = app.update(db).await.map_err(InternalServerError)?;

        context.insert("app", &app);
        let response = TEMPLATES
            .render("local_app_read.html", &context)
            .map_err(InternalServerError)?;
        Ok(Html(response).into_response())
    } else {
        Ok(Response::builder().status(StatusCode::NOT_FOUND).body(()))
    }
}

#[handler]
pub async fn local_app_delete(id: Path<u8>) -> Result<impl IntoResponse> {
    let db = get_db();

    /* delete_by_id returns a struct with a rows_affected count. If that's 0, the app wasn't deleted.
     * If more than 1, something weird happened. */
    let status = match LocalApp::Entity::delete_by_id(id.0)
        .exec(db)
        .await
        .map_err(InternalServerError)?
        .rows_affected
    {
        0 => StatusCode::NOT_FOUND,
        1 => StatusCode::OK,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    Ok(Response::builder().status(status).body(()))
}

/* *** TESTS *** */

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::load_test_app;
    use poem::test::TestClient;

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

    /* We expect the OAuth redirect URL to respond to, but not handle, random get requests. */
    #[tokio::test]
    async fn can_reach_redirect() {
        let config = get_config();
        let redirect_path = config.redirect_path.clone();
        // send request and check the status code
        let client = TestClient::new(load_test_app());
        client
            .get(format!("{redirect_path}?code=foo&state=bar"))
            .send()
            .await
            .assert_status(StatusCode::BAD_REQUEST)
    }
}

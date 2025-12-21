use oauth2::{
    AuthorizationCode, CsrfToken, EmptyExtraTokenFields, PkceCodeChallenge, Scope,
    StandardTokenResponse, TokenResponse, basic::BasicTokenType, reqwest::Client as ReqwestClient,
};
use poem::{
    IntoResponse, Response, Result,
    error::{BadRequest, Error, InternalServerError},
    handler,
    http::StatusCode,
    session::Session,
    web::{Form, Html, Multipart, Path, Query, Redirect},
};
use sea_orm::{
    ActiveModelTrait,
    ActiveValue::{NotSet, Set},
    ColumnTrait, EntityTrait, QueryFilter, QueryOrder,
    sea_query::Condition,
};
use serde::Deserialize;
use tera::Context;
use tracing::{Level, event, instrument};

use std::{
    fs::File,
    io::Write,
    path::Path as std_path,
    time::{Duration, SystemTime},
};

use super::{AppCard, AppResponse, TEMPLATES, User, get_config, get_db, get_oauth_client};

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

#[instrument(skip_all)]
async fn get_token(
    session: &Session,
) -> Result<StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>> {
    if let Some(mut token) =
        session.get::<StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>>("token")
    {
        /* We should have the expiry set in the session.
        If not, something's goofy, and we should probably try to force a refresh. */
        let expiry = match session.get::<SystemTime>("expiry") {
            Some(t) => t,
            None => SystemTime::now() - Duration::new(1, 0),
        };

        // Are we past the expiry time? If so, refresh the token.
        if SystemTime::now() > expiry {
            match token.refresh_token() {
                Some(refresh_token) => {
                    event!(Level::TRACE, "Refreshing token");
                    let client = get_oauth_client()?;

                    let new_token = client
                        .exchange_refresh_token(refresh_token)
                        .request_async(&ReqwestClient::new())
                        .await
                        .map_err(InternalServerError)?;

                    let new_expiry = SystemTime::now()
                        + new_token
                            .expires_in()
                            .unwrap_or_else(|| Duration::new(3600, 0));

                    /* We have a new token, so update the session */
                    event!(Level::TRACE, "New expiry: {:#?}", &new_expiry);
                    session.set("expiry", new_expiry);

                    token = new_token;
                    session.set("token", token.clone());

                    Ok(token)
                }
                None => Err(Error::from_string(
                    "No refresh token found",
                    StatusCode::UNAUTHORIZED,
                )),
            }
        } else {
            // The current token should still be good, so no need to refresh it
            Ok(token)
        }
    } else {
        // There is no token, that's not right
        Err(Error::from_string(
            "No access token found",
            StatusCode::UNAUTHORIZED,
        ))
    }
}

#[handler]
#[instrument(skip_all)]
pub async fn app_cards(session: &Session) -> Result<impl IntoResponse> {
    /* Send the user back to login if we can't get the access token. Is 303 the right code? */

    let mut context = Context::new();

    if let Ok(token) = get_token(session).await {
        let client = reqwest::Client::new();

        // We'll need the user's groups for determining access to our local apps
        let groups = session
            .get::<User>("user")
            .expect("No user found in session")
            .groups
            .unwrap_or(vec![]);

        /* This vec will hold our apps, whether from Authentik or the DB */
        let mut applications: Vec<AppCard> = Vec::new();

        let config = get_config();

        let applications_endpoint = config
            .authentik_url
            .join("api/v3/core/applications/")
            .expect("Could not construct Authentik API URL");

        let mut response = client
            .get(applications_endpoint)
            .bearer_auth(token.access_token().secret())
            .send()
            .await
            .map_err(InternalServerError)?;

        if response.status().is_success() {
            let auth_apps = response
                .json::<AppResponse>()
                .await
                .map_err(InternalServerError)?;

            applications.append(
                    &mut auth_apps
                        .results
                        .into_iter()
                        /* Let's not include this app in the application list */
                        .filter(|app| app.name.to_lowercase() != config.syn_provider.to_lowercase())
                        /* Follow Authentik's behavior of hiding apps with a launch URL of blank://blank */
                        .filter(|app| app.launch_url.to_lowercase() != "blank://blank")
                        .map(|a| a.into())
                        .collect(),
                );

            /* local applications */
            let db = get_db();
            applications.append(
                &mut LocalApp::Entity::find()
                    .filter(
                        // Same behavior as Authentik: Limit to apps in groups the user belongs to, or are not in a group
                        Condition::any()
                            .add(LocalApp::Column::Group.is_in(groups))
                            .add(LocalApp::Column::Group.eq("")),
                    )
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
            event!(Level::DEBUG, "{}", response.text().await.unwrap());
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
#[instrument(skip(session))]
pub async fn login(session: &Session) -> Result<impl IntoResponse> {
    let client = get_oauth_client()?;

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
    event!(Level::INFO, "login initiated");
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

    let client = get_oauth_client()?;
    let config = get_config();

    let token = client
        .exchange_code(AuthorizationCode::new(code))
        .set_pkce_verifier(pkce_verifier)
        .request_async(&ReqwestClient::new())
        .await
        .map_err(InternalServerError)?;

    let expiry = SystemTime::now() + token.expires_in().unwrap_or_else(|| Duration::new(3600, 0));

    let client = reqwest::Client::new();

    let user_data: User = {
        // Wrapping this in an expression because we only need mutability for a moment
        let mut ud = client
            .get(config.openid.userinfo_endpoint.clone())
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
    Redirect::permanent(config.openid.end_session_endpoint.clone())
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
pub async fn post_local_app(
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
        icon: Set(icon),
        description: Set(description),
        group: Set(group),
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
pub async fn get_edit_local_app(id: Path<u8>) -> Result<impl IntoResponse> {
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
pub async fn get_new_local_app() -> Result<impl IntoResponse> {
    let mut context = Context::new();

    let response = TEMPLATES
        .render("local_app_create.html", &context)
        .map_err(InternalServerError)?;
    Ok(Html(response).into_response())
}

#[handler]
pub async fn get_local_app(id: Path<u8>) -> Result<impl IntoResponse> {
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
pub async fn put_local_app(
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
        app.icon = Set(icon);
        app.description = Set(description);
        app.group = Set(group);

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
pub async fn delete_local_app(id: Path<u8>) -> Result<impl IntoResponse> {
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

#[handler]
pub async fn get_icon_form(id: Path<u8>) -> Result<impl IntoResponse> {
    let db = get_db();

    let mut context = Context::new();

    if let Some(app) = LocalApp::Entity::find_by_id(id.0)
        .one(db)
        .await
        .map_err(InternalServerError)?
    {
        context.insert("app", &app);

        let response = TEMPLATES
            .render("icon_form.html", &context)
            .map_err(InternalServerError)?;
        Ok(Html(response).into_response())
    } else {
        Ok(Response::builder().status(StatusCode::NOT_FOUND).body(()))
    }
}

#[handler]
pub async fn post_icon_form(id: Path<u8>, mut multipart: Multipart) -> Result<impl IntoResponse> {
    let db = get_db();

    if let Some(app) = LocalApp::Entity::find_by_id(id.0)
        .one(db)
        .await
        .map_err(InternalServerError)?
    {
        let mut app: LocalApp::ActiveModel = app.into();

        // There should only be one field in the form
        while let Ok(Some(field)) = multipart.next_field().await {
            let file_name = field.file_name().map(ToString::to_string);
            if let Ok(bytes) = field.bytes().await {
                // Where does this app keep its icon files?
                let location = format!("media/application-icons/{0}", id.0);

                // Create the icon directory for the app if it doesn't already have one
                std::fs::create_dir_all(location.clone()).map_err(InternalServerError)?;

                /* Leaving a few unlikely scenarios as expects here. Should map to a server error eventually,
                 * but need better error logging first */

                // Construct the full path where we'll upload the icon file, keeping the filename intact
                let path =
                    std_path::new(&location).join(file_name.expect("File upload has no filename"));

                app.icon = Set(path
                    .clone()
                    .into_os_string()
                    .into_string()
                    .expect("Could not convert the icon image path to UTF-8 string"));

                let mut file = File::create(path).map_err(InternalServerError)?;
                file.write(&bytes).map_err(InternalServerError)?;
            }
        }

        app.update(db).await.map_err(InternalServerError)?;
        Ok(Response::builder()
            .status(StatusCode::NO_CONTENT)
            .header("HX-Trigger", format!("iconSaved_{0}", id.0))
            .body(()))
    } else {
        Ok(Response::builder().status(StatusCode::NOT_FOUND).body(()))
    }
}

/* *** TESTS *** */

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::load_test_app;
    use poem::test::TestClient;

    /* Remember to use flavor = "multi_thread" for any tests that use CONFIG (even indirectly).
    This is because we use block_in_place to construct that, which requires multithreading. */

    /* We expect the main index to be generally reachable */
    #[tokio::test(flavor = "multi_thread")]
    async fn can_reach_index() {
        let client = TestClient::new(load_test_app());
        client.get("/").send().await.assert_status_is_ok();
    }

    /* We expect the login page to redirect to Authentik */
    #[tokio::test(flavor = "multi_thread")]
    async fn can_reach_login() {
        let client = TestClient::new(load_test_app());
        client
            .get("/login")
            .send()
            .await
            .assert_status(StatusCode::SEE_OTHER)
    }

    /* We expect the logout page to redirect back home */
    #[tokio::test(flavor = "multi_thread")]
    async fn can_reach_logout() {
        let client = TestClient::new(load_test_app());
        client
            .get("/logout")
            .send()
            .await
            .assert_status(StatusCode::PERMANENT_REDIRECT)
    }

    /* We expect the OAuth redirect URL to respond to, but not handle, random get requests. */
    #[tokio::test(flavor = "multi_thread")]
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

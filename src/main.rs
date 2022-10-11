use lazy_static::lazy_static;
use oauth2::{
    basic::BasicClient, reqwest::async_http_client, AuthUrl, AuthorizationCode, ClientId,
    ClientSecret, CsrfToken, RedirectUrl, Scope, TokenResponse, TokenUrl,
};
use poem::{
    error::{Error, NotFoundError},
    get, handler,
    http::StatusCode,
    listener::TcpListener,
    middleware::{Csrf, Tracing},
    session::{CookieConfig, RedisStorage, ServerSession, Session},
    web::{Html, Query, Redirect},
    EndpointExt, IntoResponse, Route, Server,
};
use redis::aio::ConnectionManager;
use serde::{Deserialize, Deserializer, Serialize};
use std::env;
use tera::{Context, Tera};

lazy_static! {
    pub static ref TEMPLATES: Tera = {
        let mut tera = match Tera::new("templates/**/*") {
            Ok(t) => t,
            Err(e) => {
                println!("Parsing error(s): {}", e);
                ::std::process::exit(1);
            }
        };
        tera.autoescape_on(vec![".html", ".sql"]);
        tera
    };
}

#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
    dotenv::dotenv().ok();

    if env::var_os("RUST_LOG").is_none() {
        env::set_var("RUST_LOG", "poem=debug");
    }

    tracing_subscriber::fmt::init();

    // If $REDIS_URL is not present, assume it's in a Docker container with the hostname "redis"
    let redis_url = env::var("SYN_REDIS_URL").unwrap_or_else(|_| "redis".to_string());
    let redis = redis::Client::open(format!("redis://{redis_url}/")).unwrap();

    let redirect_path = env::var("SYN_REDIRECT_PATH").expect("Missing REDIRECT_PATH!");

    let app = Route::new()
        .at("/", get(index))
        .at("/login", get(login))
        .at("/logout", get(logout))
        .at(redirect_path, get(login_authorized))
        .catch_error(four_oh_four)
        .with(Tracing)
        .with(Csrf::new())
        //.with(CookieSession::new(CookieConfig::default().secure(false)));
        .with(ServerSession::new(
            CookieConfig::default(),
            RedisStorage::new(ConnectionManager::new(redis).await.unwrap()),
        ));

    let port = dotenv::var("SYN_PORT").expect("No $PORT is set");

    Server::new(TcpListener::bind(format!("0.0.0.0:{port}")))
        .name("synalpheus")
        .run(app)
        .await
}

#[handler]
async fn index(session: &Session) -> impl IntoResponse {
    let mut context = Context::new();
    if let Some(user) = session.get::<User>("user") {
        let client = reqwest::Client::new();

        let refresh_token = session.get::<String>("refresh_token").unwrap();

        let authentik_url = dotenv::var("SYN_AUTHENTIK_URL").expect("Cannot get Authentik URL");

        let mut apps = client
            .get(format!("{authentik_url}/api/v3/core/applications"))
            .bearer_auth(refresh_token.clone())
            .send()
            .await
            .expect("Request failed")
            .json::<AppResponse>()
            .await
            .expect("JSON failed");

        apps.results.sort_by_key(|app| app.group.clone());

        context.insert("user", &user);
        context.insert("apps", &apps.results);
    };
    let response = TEMPLATES.render("index.html", &context).unwrap();
    Html(response).into_response()
}

#[handler]
async fn login(session: &Session) -> impl IntoResponse {
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
async fn login_authorized(
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
async fn logout(session: &Session) -> Redirect {
    session.purge();
    Redirect::permanent("/")
}

async fn four_oh_four(_: NotFoundError) -> impl IntoResponse {
    let response = TEMPLATES.render("404.html", &Context::new()).unwrap();
    Html(response)
        .into_response()
        .with_status(StatusCode::NOT_FOUND)
}

fn oauth_client() -> BasicClient {
    let authentik_url = dotenv::var("SYN_AUTHENTIK_URL").expect("Cannot get Authentik URL");

    let client_id = env::var("SYN_CLIENT_ID").expect("Missing CLIENT_ID!");
    let client_secret = env::var("SYN_CLIENT_SECRET").expect("Missing CLIENT_SECRET!");
    let redirect_url = env::var("SYN_REDIRECT_URL").expect("Missing REDIRECT_URL!");

    /* These do not appear to be editable, so we can construct them here rather than in the .env */
    let authorize_url = format!("{authentik_url}/application/o/authorize/");
    let token_url = format!("{authentik_url}/application/o/token/");

    BasicClient::new(
        ClientId::new(client_id),
        Some(ClientSecret::new(client_secret)),
        AuthUrl::new(authorize_url).unwrap(),
        Some(TokenUrl::new(token_url).unwrap()),
    )
    .set_redirect_uri(RedirectUrl::new(redirect_url).unwrap())
}

#[derive(Debug, Deserialize)]
struct AuthRequest {
    code: String,
    state: CsrfToken,
}

#[derive(Debug, Serialize, Deserialize)]
struct User {
    email: String,
    name: String,
    //#[serde(rename(deserialize = "preferred_username"))]
    preferred_username: String,
    groups: Option<Vec<String>>,
    sub: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
struct AppResponse {
    pagination: Option<Pagination>,
    results: Vec<Application>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
struct Pagination {
    next: i64,
    previous: i64,
    count: i64,
    current: i64,
    total_pages: i64,
    start_index: i64,
    end_index: i64,
}

/* We probably don't need all these fields */
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
struct Application {
    pk: String,
    name: String,
    slug: String,
    #[serde(deserialize_with = "deserde_null_field")]
    provider: i64,
    #[serde(deserialize_with = "deserde_null_field")]
    launch_url: String,
    open_in_new_tab: bool,
    meta_launch_url: String,
    #[serde(deserialize_with = "deserde_icon_url")]
    meta_icon: String,
    meta_description: String,
    meta_publisher: String,
    policy_engine_mode: String,
    group: String,
}

/* Some fields are optional in Authentik, and are present in the API response as nulls.
 * When that happens, we have to change the null to an empty string */
fn deserde_null_field<'de, D, T>(de: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    let key = Option::<T>::deserialize(de)?;
    Ok(key.unwrap_or_default())
}

/* Not only is the meta_icon field nullable, but it's also a relative path on Authentik's domain.
 * Here we handle null values and also convert it to an absolute path so we can use them.
 * Fortunately we know this field is always going to be a string */
fn deserde_icon_url<'de, D>(de: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let authentik_url = dotenv::var("SYN_AUTHENTIK_URL").expect("Cannot get Authentik URL");

    let url = match Option::<String>::deserialize(de)? {
        Some(key) => format!("{authentik_url}{key}"),
        None => String::default(),
    };

    Ok(url)
}

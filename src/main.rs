use askama::Template;
use oauth2::{
    basic::BasicClient, reqwest::async_http_client, AuthUrl, AuthorizationCode, ClientId,
    ClientSecret, CsrfToken, RedirectUrl, Scope, TokenResponse, TokenUrl,
};
use poem::{
    get, handler,
    listener::TcpListener,
    middleware::Tracing,
    session::{CookieConfig, CookieSession, Session},
    web::{Html, Query, Redirect},
    EndpointExt, IntoResponse, Route, Server,
};
use serde::{Deserialize, Serialize};
use std::{env, ops::Index};

fn oauth_client() -> BasicClient {
    let authentik_url = dotenv::var("AUTHENTIK_URL").expect("Cannot get Authentik URL");

    let client_id = env::var("CLIENT_ID").expect("Missing CLIENT_ID!");
    let client_secret = env::var("CLIENT_SECRET").expect("Missing CLIENT_SECRET!");
    let redirect_url = env::var("REDIRECT_URL").expect("Missing REDIRECT_URL!");

    /* These do not appear to be editable, so construct them here rather than in the .env */
    let authorize_url = format!("{authentik_url}/application/o/authorize/");
    let token_url = format!("{authentik_url}/application/o/token/");

    println!("{}", &redirect_url);

    BasicClient::new(
        ClientId::new(client_id),
        Some(ClientSecret::new(client_secret)),
        AuthUrl::new(authorize_url).unwrap(),
        Some(TokenUrl::new(token_url).unwrap()),
    )
    .set_redirect_uri(RedirectUrl::new(redirect_url).unwrap())
}

#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var("RUST_LOG", "poem=debug");
    }
    tracing_subscriber::fmt::init();

    dotenv::dotenv().ok();

    let redirect_path = env::var("REDIRECT_PATH").expect("Missing REDIRECT_PATH!");

    let app = Route::new()
        .at("/", get(index))
        .at("/login", get(login))
        .at("/logout", get(logout))
        .at(redirect_path, get(login_authorized))
        .with(Tracing)
        .with(CookieSession::new(CookieConfig::default().secure(false)));

    let address = dotenv::var("ADDRESS").expect("Cannot get ADDRESS");

    println!("Address: {}", &address);

    Server::new(TcpListener::bind(address))
        .name("gonkboard")
        .run(app)
        .await
}

#[handler]
async fn index(session: &Session) -> impl IntoResponse {
    let response = match session.get::<User>("user") {
        Some(user) => {
            let client = reqwest::Client::new();

            let refresh_token = session.get::<String>("refresh_token").unwrap();

            let authentik_url = dotenv::var("AUTHENTIK_URL").expect("Cannot get Authentik URL");

            let apps = client
                .get(format!("{authentik_url}/api/v3/core/applications"))
                .bearer_auth(refresh_token.clone())
                .send()
                .await
                .expect("Request failed")
                .json::<AppResponse>()
                .await
                .expect("JSON failed");

            UserTemplate {
                user: &user,
                apps: &apps.results,
            }
            .render()
            .unwrap()
        }
        None => AnonTemplate {}.render().unwrap(),
    };
    Html(response).into_response()
}

#[handler]
async fn login() -> Redirect {
    let client = oauth_client();
    let (auth_url, _csrf_token) = client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("openid".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("goauthentik.io/api".to_string()))
        .url();

    println!("{:#?}", &auth_url);

    // Redirect to Authentik
    Redirect::permanent(auth_url)
}

#[handler]
async fn login_authorized(
    session: &Session,
    Query(AuthRequest { code, state: _ }): Query<AuthRequest>,
) -> Redirect {
    let client = oauth_client();
    let token = client
        .exchange_code(AuthorizationCode::new(code))
        .request_async(async_http_client)
        .await
        .unwrap();

    let client = reqwest::Client::new();
    let refresh_token = token.refresh_token().unwrap().secret();

    let authentik_url = dotenv::var("AUTHENTIK_URL").expect("Cannot get Authentik URL");

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

    Redirect::permanent("/")
}

#[handler]
async fn logout(session: &Session) -> impl IntoResponse {
    session.purge();

    Redirect::permanent("/")
}

#[derive(Template)]
#[template(path = "index.html")]
struct UserTemplate<'a> {
    user: &'a User,
    apps: &'a Vec<Application>,
}

#[derive(Template)]
#[template(path = "anon.html")]
struct AnonTemplate {}

#[derive(Debug, Deserialize)]
struct AuthRequest {
    code: String,
    state: String,
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

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
struct Application {
    pk: String,
    name: String,
    slug: String,
    provider: Option<i64>,
    launch_url: Option<String>,
    open_in_new_tab: bool,
    meta_launch_url: String,
    meta_icon: Option<String>,
    meta_description: String,
    meta_publisher: String,
    policy_engine_mode: String,
    group: String,
}

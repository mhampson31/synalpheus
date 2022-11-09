use lazy_static::lazy_static;
use oauth2::{basic::BasicClient, AuthUrl, ClientId, ClientSecret, RedirectUrl, TokenUrl};
use poem::{
    error::NotFoundError,
    get,
    http::StatusCode,
    listener::TcpListener,
    middleware::{CatchPanic, Csrf, Tracing},
    session::{CookieConfig, RedisStorage, ServerSession},
    web::Html,
    Endpoint, EndpointExt, IntoResponse, Route, Server,
};
use redis::aio::ConnectionManager;
use serde::{Deserialize, Deserializer, Serialize};
use std::env;
use tera::{Context, Tera};

mod routes;

lazy_static! {
    pub static ref TEMPLATES: Tera = {
        /* Tera::new(glob) seems to lead to a hang with 100% CPU on Docker.
         *  https://github.com/Keats/tera/issues/719
         */
        let mut tera = Tera::default();

        tera.add_template_files(vec![
            ("templates/404.html", Some("404.html")),
            ("templates/base.html", Some("base.html")),
            ("templates/index.html", Some("index.html")),
        ])
        .unwrap();

        tera.autoescape_on(vec![".html", ".sql"]);
        tera
    };
}

/* This creates our actual application. We call this out into a seperate function so
 * we can build a nearly-identical app for our testing.
 * The main difference is that we do not configure the session types here, since test
 * functions will not use Redis. */
fn create_app() -> impl Endpoint {
    let redirect_path = env::var("SYN_REDIRECT_PATH").expect("Missing SYN_REDIRECT_PATH!");

    Route::new()
        .at("/", get(routes::index))
        .at("/login", get(routes::login))
        .at("/logout", get(routes::logout))
        .at(redirect_path, get(routes::login_authorized))
        .catch_error(four_oh_four)
        .with(Tracing)
        .with(Csrf::new())
        .with(CatchPanic::new())
}

#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
    dotenv::dotenv().ok();

    if env::var_os("RUST_LOG").is_none() {
        env::set_var("RUST_LOG", "poem=debug");
    }

    tracing_subscriber::fmt::init();

    let app = create_app();

    // If $SYN_REDIS_URL is not present, assume it's in a Docker container with the hostname "redis"
    let redis = env::var("SYN_REDIS_URL").unwrap_or_else(|_| "redis".to_string());
    let redis = redis::Client::open(format!("redis://{redis}/")).unwrap();

    /* There might be a better way to do this. Basically, we need to block on the async ConnectionManager
     * in order to hand an actual connection to the middleware, not just a future.
     * */
    let redis_conn = futures::executor::block_on(ConnectionManager::new(redis))
        .expect("Could not connect to Redis.");

    let app = app.with(ServerSession::new(
        CookieConfig::default(),
        RedisStorage::new(redis_conn),
    ));

    // If $SYN_PORT is not present, run on 80
    let port = env::var("SYN_PORT").unwrap_or_else(|_| "80".to_string());
    Server::new(TcpListener::bind(format!("0.0.0.0:{port}")))
        .name("synalpheus")
        .run(app)
        .await
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

/* *** TESTS *** */

#[cfg(test)]
mod tests {
    use super::*;
    use poem::{session::CookieSession, test::TestClient};

    /* A helper function that mocks a response from Authentik, not a test itself */
    fn load_sample_apps_response() -> Result<AppResponse, serde_json::Error> {
        let test_data = std::fs::read_to_string("test_data/get-applications-response.json")
            .expect("Unable to read test data file");
        serde_json::from_str(&test_data)
    }

    /* A helper function to simplify the boilerplate of spinning up the app */
    fn load_test_app() -> impl Endpoint {
        let app = create_app();
        app.with(CookieSession::new(CookieConfig::default().secure(false)))
    }

    /* Actual tests begin here */

    /* Can we deserialize a user's GET response from Authentik's core/applications endpoint?  */
    #[test]
    fn can_parse_applications_response() {
        let response = load_sample_apps_response();
        assert!(response.is_ok())
    }

    /* Are we handling null fields correctly when we deserialize the API responses? */
    #[test]
    fn can_deserde_null_field() {
        let data = r#"
        {
            "nullable_int": null,
            "nullable_string": null
        }"#;

        #[derive(Deserialize, PartialEq, Debug)]
        struct NullFieldTester {
            #[serde(deserialize_with = "deserde_null_field")]
            nullable_int: i64,
            #[serde(deserialize_with = "deserde_null_field")]
            nullable_string: String,
        }

        let control = NullFieldTester {
            nullable_int: 0,
            nullable_string: "".to_string(),
        };

        let result: NullFieldTester = serde_json::from_str(data).unwrap();

        assert_eq!(control, result)
    }

    /* Can we convert Authentik's icon URLs from relative to absolute paths correctly?
     * And we need to account for potentially null URLs too. */
    #[test]
    fn can_deserde_icon_url() {
        let data = r#"
        {
            "icon": "/test.png",
            "null_icon": null
        }"#;

        #[derive(Deserialize, PartialEq, Debug)]
        struct IconURLTester {
            #[serde(deserialize_with = "deserde_icon_url")]
            icon: String,
            #[serde(deserialize_with = "deserde_icon_url")]
            null_icon: String,
        }

        let authentik_url = dotenv::var("SYN_AUTHENTIK_URL").expect("Cannot get Authentik URL");

        let control = IconURLTester {
            icon: format!("{authentik_url}/test.png"),
            null_icon: "".to_string(),
        };

        let result: IconURLTester = serde_json::from_str(data).unwrap();

        assert_eq!(control, result)
    }

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

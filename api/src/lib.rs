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
    EndpointExt, IntoResponse, Route, Server,
};
use redis::aio::ConnectionManager;
use sea_orm::Database;
use serde::{Deserialize, Deserializer, Serialize};
use std::env;
use tera::{Context, Tera};

use migration::{Migrator, MigratorTrait};

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

#[tokio::main]
async fn start() -> std::io::Result<()> {
    dotenv::dotenv().ok();

    if env::var_os("RUST_LOG").is_none() {
        env::set_var("RUST_LOG", "poem=debug");
    }

    tracing_subscriber::fmt::init();

    // If $SYN_REDIS_URL is not present, assume it's in a Docker container with the hostname "redis"
    let redis_url = env::var("SYN_REDIS_URL").unwrap_or_else(|_| "redis".to_string());
    let redis = redis::Client::open(format!("redis://{redis_url}/")).unwrap();

    // Postgres initialization
    let connection = env::var("SYN_POSTGRES_URL").expect("Missing Postgres connection string!");

    let connection = Database::connect(&connection).await.unwrap();
    Migrator::up(&connection, None).await.unwrap();

    let redirect_path = env::var("SYN_REDIRECT_PATH").expect("Missing SYN_REDIRECT_PATH!");

    let app = Route::new()
        .at("/", get(routes::index))
        .at("/login", get(routes::login))
        .at("/logout", get(routes::logout))
        .at(redirect_path, get(routes::login_authorized))
        .catch_error(four_oh_four)
        .with(Tracing)
        .with(Csrf::new())
        .with(CatchPanic::new())
        //.with(CookieSession::new(CookieConfig::default().secure(false)));
        .with(ServerSession::new(
            CookieConfig::default(),
            RedisStorage::new(ConnectionManager::new(redis).await.unwrap()),
        ));

    // If $SYN_PORT is not present, run on 80
    let port = env::var("SYN_PORT").unwrap_or_else(|_| "80".to_string());
    Server::new(TcpListener::bind(format!("0.0.0.0:{port}")))
        .name("synalpheus")
        .run(app)
        .await
}

pub fn main() {
    let result = start();

    if let Some(err) = result.err() {
        println!("Error: {}", err);
    }
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

// The User struct comes from entity

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

/* *** tests *** */

#[cfg(test)]
mod tests {
    use super::*;
    use entity::{application, user};
    use poem::{session::CookieSession, test::TestClient};
    use sea_orm::{entity::prelude::*, DatabaseBackend, MockDatabase};

    /* A helper function, not a test itself */
    fn load_sample_apps_response() -> Result<AppResponse, serde_json::Error> {
        let test_data = std::fs::read_to_string("test_data/get-applications-response.json")
            .expect("Unable to read test data file");
        serde_json::from_str(&test_data)
    }

    /* A helper function to set up a mock database */
    fn load_sample_db() -> sea_orm::DatabaseConnection {
        MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results(vec![vec![
                user::Model {
                    id: 1,
                    name: "Alice".to_owned(),
                    email: "alice at email.com".to_owned(),
                    preferred_username: "Alice".to_owned(),
                    groups: None,
                    sub: "".to_owned(),
                },
                user::Model {
                    id: 2,
                    name: "Bob".to_owned(),
                    email: "bob at email.com".to_owned(),
                    preferred_username: "Bob".to_owned(),
                    groups: None,
                    sub: "".to_owned(),
                },
                user::Model {
                    id: 3,
                    name: "Charlie".to_owned(),
                    email: "charlie at email.com".to_owned(),
                    preferred_username: "Charlie".to_owned(),
                    groups: None,
                    sub: "".to_owned(),
                },
            ]])
            .append_query_results(vec![vec![
                application::Model {
                    id: 1,
                    name: "App 1".to_owned(),
                    slug: "app1".to_owned(),
                    launch_url: "localhost/app1".to_owned(),
                    open_in_new_tab: true,
                    icon: "localhost/app1/icon.png".to_owned(),
                    group: "Testing".to_owned(),
                },
                application::Model {
                    id: 2,
                    name: "App 2".to_owned(),
                    slug: "app2".to_owned(),
                    launch_url: "localhost/app2".to_owned(),
                    open_in_new_tab: false,
                    icon: "localhost/app2/icon.png".to_owned(),
                    group: "".to_owned(),
                },
            ]])
            .into_connection()
    }

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

    #[tokio::test]
    async fn can_reach_index() {
        let app = Route::new()
            .at("/", get(routes::index))
            .catch_error(four_oh_four)
            .with(Csrf::new())
            .with(CatchPanic::new())
            .with(CookieSession::new(CookieConfig::default().secure(false)));

        let cli = TestClient::new(app);

        // send request
        let resp = cli.get("/").send().await;
        // check the status code
        resp.assert_status_is_ok();
    }

    #[tokio::test]
    async fn can_find_one_user() {
        let db = load_sample_db();

        // Return the first query result
        assert_eq!(
            user::Entity::find().one(&db).await.unwrap(),
            Some(user::Model {
                id: 1,
                name: "Alice".to_owned(),
                email: "alice at email.com".to_owned(),
                // pref username is not actually save in the DB, so a passing test here is an empty string
                preferred_username: "".to_owned(),
                groups: None,
                sub: "".to_owned(),
            })
        );
    }

    #[tokio::test]
    async fn can_find_all_users() {
        let db = load_sample_db();

        assert_eq!(
            user::Entity::find().all(&db).await.unwrap(),
            vec![
                user::Model {
                    id: 1,
                    name: "Alice".to_owned(),
                    email: "alice at email.com".to_owned(),
                    preferred_username: "".to_owned(),
                    groups: None,
                    sub: "".to_owned(),
                },
                user::Model {
                    id: 2,
                    name: "Bob".to_owned(),
                    email: "bob at email.com".to_owned(),
                    preferred_username: "".to_owned(),
                    groups: None,
                    sub: "".to_owned(),
                },
                user::Model {
                    id: 3,
                    name: "Charlie".to_owned(),
                    email: "charlie at email.com".to_owned(),
                    preferred_username: "".to_owned(),
                    groups: None,
                    sub: "".to_owned(),
                },
            ]
        );
    }
}

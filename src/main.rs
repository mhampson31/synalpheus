use oauth2::{basic::BasicClient, AuthUrl, ClientId, ClientSecret, RedirectUrl, TokenUrl};

use poem::{
    endpoint::{StaticFileEndpoint, StaticFilesEndpoint},
    error::{InternalServerError, NotFoundError},
    get,
    http::StatusCode,
    listener::TcpListener,
    middleware::{CatchPanic, Csrf, Tracing},
    session::{CookieConfig, RedisStorage, ServerSession, Session},
    web::Html,
    Endpoint, EndpointExt, Error, FromRequest, IntoResponse, Request, RequestBody, Result, Route,
    Server,
};

use redis::aio::ConnectionManager;
use sea_orm::{Database, DatabaseConnection};
use serde::{Deserialize, Deserializer, Serialize};
use std::env;
use std::sync::{LazyLock, OnceLock};
use tera::{Context, Tera};
use tracing::{event, instrument, Level};
use url::Url;

use migration::{Migrator, MigratorTrait};

mod data;
mod middleware;
mod routes;

//pub static TEMPLATES: Lazy<Tera> = Lazy::new(|| {
pub static TEMPLATES: LazyLock<Tera> = LazyLock::new(|| {
    /* Tera::new(glob) seems to lead to a hang with 100% CPU on Docker.
     *  https://github.com/Keats/tera/issues/719
     */
    let mut tera = Tera::default();

    tera.add_template_files(vec![
        ("templates/404.html", Some("404.html")),
        ("templates/base.html", Some("base.html")),
        ("templates/index.html", Some("index.html")),
        ("templates/app_cards.html", Some("app_cards.html")),
        ("templates/admin.html", Some("admin.html")),
        (
            "templates/local_apps/local_apps.html",
            Some("local_apps.html"),
        ),
        (
            "templates/local_apps/create.html",
            Some("local_app_create.html"),
        ),
        (
            "templates/local_apps/read.html",
            Some("local_app_read.html"),
        ),
        (
            "templates/local_apps/update.html",
            Some("local_app_update.html"),
        ),
        (
            "templates/local_apps/icon_form.html",
            Some("icon_form.html"),
        ),
    ])
    .expect("Template files could not be loaded");

    tera.autoescape_on(vec![".html", ".sql"]);
    tera
});

#[derive(Debug, Serialize, Deserialize, Clone)]
struct OpenID {
    issuer: Url,
    authorization_endpoint: Url,
    token_endpoint: Url,
    userinfo_endpoint: Url,
    end_session_endpoint: Url,
    introspection_endpoint: Url,
    revocation_endpoint: Url,
    device_authorization_endpoint: Url,
}

#[cfg(not(test))]
fn get_openid(well_known: Url) -> Result<OpenID> {
    /* We'll get our OpenID endpoints from Authentik.
    To do this, we'll use a quick blocking task while we make the request to Authentik.
    This only happens on initial startup, so shouldn't be a big deal. */

    // Todo: better error handling. What if it's not a success response?

    /* This can get flagged as bot activity. Not sure if there's a better way to craft the request,
    but maybe the user agent can help to craft an exception. */
    let openid = tokio::task::block_in_place(|| {
        let openid = reqwest::blocking::Client::builder()
            .user_agent("Synalpheus")
            .build()
            .expect("COuld not build client")
            .get(well_known)
            .send()
            .expect("Could not get OpenID config")
            .json::<OpenID>()
            .expect("Could not parse OpenID response");

        openid
    });
    Ok(openid)
}

#[cfg(test)]
fn get_openid(_well_known: Url) -> Result<OpenID> {
    /* Dummy OpenID fields */
    let openid = OpenID {
        issuer: Url::parse("http://localhost").unwrap(),
        authorization_endpoint: Url::parse("http://localhost").unwrap(),
        token_endpoint: Url::parse("http://localhost").unwrap(),
        userinfo_endpoint: Url::parse("http://localhost").unwrap(),
        end_session_endpoint: Url::parse("http://localhost").unwrap(),
        introspection_endpoint: Url::parse("http://localhost").unwrap(),
        revocation_endpoint: Url::parse("http://localhost").unwrap(),
        device_authorization_endpoint: Url::parse("http://localhost").unwrap(),
    };
    Ok(openid)
}

/* This largely holds our Authentik information */
pub static CONFIG: OnceLock<Config> = OnceLock::new();

#[derive(Debug)]
pub struct Config {
    // Our Authentik URL
    authentik_url: Url,

    // Our Synalpheus URL
    synalpheus_url: Url,

    // The port we're running on
    port: u16,

    // The name of the provider created for Synalpheus in Authentik
    syn_provider: String,

    // A structure containing all our OpenID endpoints
    openid: OpenID,

    // Our Oauth2 configuration info
    client_id: String,
    client_secret: String,
    redirect_path: String,
}

impl Config {
    /* We'll use a lot of expect here instead of returning a Result, because the program
    really shouldn't even run if these don't work.
    Or in a few cases, we know they're not fallible operations in this context. */

    pub fn new() -> Config {
        /* Set up what we need to run Synalpheus */

        let synalpheus_url = Url::parse(dotenvy::var("SYN_URL").expect("Missing SYN_URL").as_str())
            .expect("SYN_URL is not a parsable URL");

        let port: u16 = match dotenvy::var("SYN_PORT") {
            Ok(p) => p.parse().expect("SYN_PORT is not a valid port number"),
            Err(_) => 80,
        };

        /* Set up what we need to talk to Authentik */
        let authentik_url = dotenvy::var("SYN_AUTHENTIK_URL").expect("Missing SYN_AUTHENTIK_URL");
        let authentik_url =
            Url::parse(authentik_url.as_str()).expect("SYN_AUTHENTIK_URL is not a parsable URL");

        let redirect_path =
            dotenvy::var("SYN_REDIRECT_PATH").unwrap_or_else(|_| "auth/authentik".to_string());

        let syn_provider =
            dotenvy::var("SYN_PROVIDER").unwrap_or_else(|_| "Synalpheus".to_string());

        let well_known = authentik_url
            .join(
                format!("application/o/{syn_provider}/.well-known/openid-configuration")
                    .to_lowercase() // The provider is probably uppercase, but the endpoint expects lowercase
                    .as_str(),
            )
            .expect("Couldn't construct OpenID well-known endpoint");

        let openid =
            get_openid(well_known).expect("Could not get OpenID configuration from Authentik");

        Config {
            authentik_url: authentik_url.clone(),

            syn_provider: syn_provider.clone(),

            openid: openid.clone(),

            client_id: env::var("SYN_CLIENT_ID").expect("Missing SYN_CLIENT_ID!"),

            client_secret: env::var("SYN_CLIENT_SECRET").expect("Missing SYN_CLIENT_SECRET!"),

            redirect_path: redirect_path.clone(),

            synalpheus_url: synalpheus_url.clone(),

            port,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::new()
    }
}

pub fn get_config() -> &'static Config {
    CONFIG.get_or_init(Config::new)
}

/* Database connection */
pub static DATABASE: OnceLock<DatabaseConnection> = OnceLock::new();

pub fn get_db() -> &'static DatabaseConnection {
    DATABASE.get().expect("Database has not been initialized")
}

/* This creates our actual application. We call this out into a seperate function so
 * we can build a nearly-identical app for our testing.
 * The main difference will be in the session types, which we do not configure here, since test
 * functions will not use Redis. */
fn create_app() -> impl Endpoint {
    let redirect_path = get_config().redirect_path.clone();
    Route::new()
        // static files
        .at(
            "static/css/bulma.min.css",
            StaticFileEndpoint::new("assets/css/bulma.min.css"),
        )
        .at(
            "static/css/styles.css",
            StaticFileEndpoint::new("assets/css/styles.css"),
        )
        .at(
            "favicon.svg",
            StaticFileEndpoint::new("assets/images/favicon/favicon.svg"),
        )
        .nest(
            "media/application-icons",
            StaticFilesEndpoint::new("media/application-icons").show_files_listing(),
        )
        .nest(
            "static/icons",
            StaticFilesEndpoint::new("assets/images/icons").show_files_listing(),
        )
        // page routes
        .at("/", get(routes::index))
        .at("/login", get(routes::login))
        .at("/logout", get(routes::logout))
        .at("/admin", get(routes::admin).with(middleware::RequireAdmin))
        // internal API routes
        .at(
            "/local-apps/:id",
            get(routes::get_local_app)
                .put(routes::put_local_app)
                .delete(routes::delete_local_app)
                .with(middleware::RequireAdmin),
        )
        .at(
            "/local-apps/:1/edit",
            get(routes::get_edit_local_app).with(middleware::RequireAdmin),
        )
        .at(
            "/local-apps/new",
            get(routes::get_new_local_app).with(middleware::RequireAdmin),
        )
        .at(
            "/local-apps/icon-form/:1",
            get(routes::get_icon_form)
                .post(routes::post_icon_form)
                .with(middleware::RequireAdmin),
        )
        .at(
            "/local-apps",
            get(routes::local_apps)
                .post(routes::post_local_app)
                .with(middleware::RequireAdmin),
        )
        .at("/app-cards", get(routes::app_cards))
        .at(redirect_path, get(routes::login_authorized))
        // errors
        .catch_error(four_oh_four)
        //middleware
        .with(Tracing)
        .with(Csrf::new())
        .with(CatchPanic::new())
}

#[tokio::main]
#[instrument]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();

    if env::var_os("RUST_LOG").is_none() {
        env::set_var("RUST_LOG", "error,poem=debug,synalpheus=trace");
    }
    tracing_subscriber::fmt::init();

    event!(Level::TRACE, "starting Synalpheus server");

    CONFIG.set(Config::new()).unwrap();
    let config = get_config();

    event!(Level::INFO, "Connecting to database");
    let postgres = env::var("SYN_POSTGRES_URL").expect("Missing SYN_POSTGRES_URL");
    let db = Database::connect(postgres)
        .await
        .expect("Could not connect to database");

    println!("Performing migrations...");
    Migrator::up(&db, None).await.map_err(InternalServerError)?;

    DATABASE.set(db).unwrap();

    println!("Creating application...");
    let app = create_app();

    // If $SYN_REDIS_URL is not present, assume it's in a Docker container with the hostname "redis"
    let redis = env::var("SYN_REDIS_URL").unwrap_or_else(|_| "redis".to_string());
    let redis = redis::Client::open(format!("redis://{redis}/")).map_err(InternalServerError)?;

    let app = app.with(ServerSession::new(
        CookieConfig::default(),
        RedisStorage::new(
            ConnectionManager::new(redis)
                .await
                .map_err(InternalServerError)?,
        ),
    ));

    // If $SYN_PORT is not present, we run on 80.
    // url::Url's port methods will probably return a None in our default cases
    let port = config.port;

    Server::new(TcpListener::bind(format!("0.0.0.0:{port}")))
        .name("synalpheus")
        .run(app)
        .await
        .map_err(InternalServerError)
}

async fn four_oh_four(_: NotFoundError) -> impl IntoResponse {
    let response = TEMPLATES
        .render("404.html", &Context::new())
        .expect("Template failure");

    Html(response)
        .into_response()
        .with_status(StatusCode::NOT_FOUND)
}

fn get_oauth_client() -> Result<BasicClient> {
    let config = CONFIG.get_or_init(Config::new);

    match config.synalpheus_url.join(config.redirect_path.as_str()) {
        Ok(redirect_url) => Ok(BasicClient::new(
            ClientId::new(config.client_id.clone()),
            Some(ClientSecret::new(config.client_secret.clone())),
            AuthUrl::from_url(config.openid.authorization_endpoint.clone()),
            Some(TokenUrl::from_url(config.openid.token_endpoint.clone())),
        )
        .set_redirect_uri(RedirectUrl::from_url(redirect_url))),
        Err(e) => Err(Error::from_string(
            "Cannot parse Oath2 URLs",
            StatusCode::INTERNAL_SERVER_ERROR,
        )),
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct User {
    email: String,
    name: String,
    preferred_username: String,
    groups: Option<Vec<String>>,
    sub: String,
    #[serde(default)]
    is_superuser: bool,
}

/* An extractor to easily get the user in a route function */
impl<'a> FromRequest<'a> for User {
    async fn from_request(req: &'a Request, _: &mut RequestBody) -> Result<Self> {
        let user = req
            .extensions()
            .get::<Session>()
            .ok_or_else(|| poem::Error::from_string("missing session", StatusCode::FORBIDDEN))?
            .get::<User>("user")
            .ok_or_else(|| poem::Error::from_string("missing user", StatusCode::FORBIDDEN))?;
        Ok(user)
    }
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
struct AppResponse {
    pagination: Option<Pagination>,
    results: Vec<AuthentikApp>,
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

/* This doesn't currently need to do anything
   Todo: document why this needs to exist here
*/

trait Application {}

/* We probably don't need all these fields */
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthentikApp {
    pk: String,
    name: String,
    slug: String,
    #[serde(deserialize_with = "deserde_null_field")]
    provider: i64,
    #[serde(deserialize_with = "deserde_null_field")]
    launch_url: String,
    open_in_new_tab: bool,
    meta_launch_url: String,
    #[serde(
        deserialize_with = "deserde_icon_url",
        rename(deserialize = "meta_icon")
    )]
    icon: String,
    #[serde(rename(deserialize = "meta_description"))]
    description: String,
    meta_publisher: String,
    policy_engine_mode: String,
    group: String,
}

/* We have two sources for applications right now, Authentik and our local data via SeaORM.
 * This will let us homogenize them for passing to a response context.*/

#[derive(Default, Clone, Debug, PartialEq, Serialize, Deserialize)]
enum Source {
    #[default]
    Authentik,
    Local,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AppCard {
    icon: String,
    name: String,
    slug: String,
    group: String,
    description: String,
    launch_url: String,
    source: Source,
}

/* Can we use generics here? The app structs are very similar. */

impl From<AuthentikApp> for AppCard {
    fn from(app: AuthentikApp) -> Self {
        AppCard {
            icon: app.icon,
            name: app.name,
            slug: app.slug,
            group: app.group,
            description: app.description,
            launch_url: app.launch_url,
            source: Source::Authentik,
        }
    }
}

impl From<entity::application::Model> for AppCard {
    fn from(app: entity::application::Model) -> Self {
        AppCard {
            icon: app.icon,
            name: app.name,
            slug: app.slug,
            group: app.group,
            description: app.description,
            launch_url: app.launch_url,
            source: Source::Local,
        }
    }
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
    let config = get_config();
    let authentik_url = config.authentik_url.clone();

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
    use poem::session::CookieSession;

    /* A helper function that mocks a response from Authentik, not a test itself */
    fn load_sample_apps_response() -> Result<AppResponse, serde_json::Error> {
        let test_data = std::fs::read_to_string("test_data/get-applications-response.json")
            .expect("Unable to read test data file");
        serde_json::from_str::<AppResponse>(&test_data)
    }

    /* A helper function to simplify the boilerplate of spinning up the app */
    pub fn load_test_app() -> impl Endpoint {
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

        let config = get_config();
        let control = IconURLTester {
            icon: format!("{}/test.png", config.authentik_url),
            null_icon: "".to_string(),
        };

        let result: IconURLTester = serde_json::from_str(data).unwrap();

        assert_eq!(control, result)
    }
}

use poem::{
    FromRequest, IntoResponse, Request, RequestBody, Result, Server, error::InternalServerError,
    http::StatusCode, listener::TcpListener, session::Session,
};

use sea_orm::{Database, DatabaseConnection, EntityTrait, QueryFilter, sea_query::Condition};
use serde::{Deserialize, Deserializer, Serialize};
use std::fs;
use std::sync::{LazyLock, OnceLock};
use tera::Tera;
use tracing::{Level, event, instrument};
use tracing_subscriber;
use url::Url;

use entity::application as LocalApp;
use migration::{Migrator, MigratorTrait};

mod application;
mod data;
mod middleware;
mod routes;

pub static TEMPLATES: LazyLock<Tera> = LazyLock::new(|| {
    /* Tera::new(glob) seems to lead to a hang with 100% CPU on Docker.
     *  https://github.com/Keats/tera/issues/719
     */
    let mut tera = Tera::default();

    let config = CONFIG.get().unwrap();

    tera.global_context().insert("title", &config.title);

    tera.load_from_glob("templates/**/*.html")
        .expect("Could not load templates");

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

impl OpenID {
    fn fetch(well_known: Url) -> Result<OpenID> {
        /* Get OpenID endpoints from Authentik.
        To do this, we'll use a quick blocking task while we make the request to Authentik.
        This only happens on initial startup, so shouldn't be a big deal. */

        // Todo: better error handling. What if it's not a success response?

        /* This can get flagged as bot activity. Not sure if there's a better way to craft the request,
        but maybe the user agent can help to craft an exception. */

        event!(Level::INFO, "Getting OpenID config from {}", well_known);

        let openid = cfg_select! {
            /* Dummy OpenID fields for testing */
            test => OpenID {
                        issuer: Url::parse("http://localhost").unwrap(),
                        authorization_endpoint: Url::parse("http://localhost").unwrap(),
                        token_endpoint: Url::parse("http://localhost").unwrap(),
                        userinfo_endpoint: Url::parse("http://localhost").unwrap(),
                        end_session_endpoint: Url::parse("http://localhost").unwrap(),
                        introspection_endpoint: Url::parse("http://localhost").unwrap(),
                        revocation_endpoint: Url::parse("http://localhost").unwrap(),
                        device_authorization_endpoint: Url::parse("http://localhost").unwrap(),
                    },
            /* get real values from Authentik */
            _ => {
                tokio::task::block_in_place(|| {
                    reqwest::blocking::Client::builder()
                        .user_agent("Synalpheus")
                        .build()
                        .expect("Could not build client")
                        .get(well_known)
                        .send()
                        .expect("Could not get OpenID config")
                        .json::<OpenID>()
                        .expect("Could not parse OpenID response")
                })
            }
        };

        Ok(openid)
    }
}

/* This struct is just a collection of default functions for the config file.
 * Some config fields cannot be defaulted (such as the application URL) so a Default
 * impl wouldn't be appropriate -- the app should not load with placeholder info.
 */
struct ConfigDefaults {}

impl ConfigDefaults {
    fn synalpheus_port() -> u16 {
        80
    }

    fn synalpheus_title() -> String {
        "Synalpheus".to_string()
    }

    fn authentik_provider() -> String {
        "Synalpheus".to_string()
    }

    fn authentik_redirect() -> String {
        "/auth/authentik".to_string()
    }

    fn postgres_port() -> u16 {
        5432
    }

    fn postgres_dbname() -> String {
        "synalpheus".to_string()
    }
}

#[derive(Deserialize, Debug)]
pub struct SynalpheusConfig {
    url: Url,
    #[serde(default = "ConfigDefaults::synalpheus_port")]
    port: u16,
    #[serde(default = "ConfigDefaults::synalpheus_title")]
    title: String,
    authentik: AuthentikConfig,
    postgres: PostgresConfig,
    // This is an Option because it can't be initialized until after the rest of the struct.
    // Where it gets used elsewhere, the assumption is that the app would not be running if it were None
    openid: Option<OpenID>,
}

impl SynalpheusConfig {
    pub fn new() -> SynalpheusConfig {
        /* Set up what we need to run Synalpheus
         * Expect is fine here, since the app can't operate if any of these fail
         */

        /* Get instance settings from config.toml */
        let c = fs::read_to_string("config.toml").expect("Missing or unreadable config.toml");
        let mut config: SynalpheusConfig = toml::from_str(&c).expect("Could not parse config.toml");

        /* Use the Authentik config from the file to get the OpenID data */
        config.openid = Some(
            OpenID::fetch(config.authentik.well_known())
                .expect("Could not get OpenID values from Authentik"),
        );

        config
    }
}

#[derive(Deserialize, Debug)]
struct AuthentikConfig {
    url: Url,
    client_id: String,
    client_secret: String,
    #[serde(default = "ConfigDefaults::authentik_provider")]
    provider: String,
    #[serde(default = "ConfigDefaults::authentik_redirect")]
    redirect: String,
}

impl AuthentikConfig {
    fn well_known(&self) -> Url {
        self.url
            .join(
                format!(
                    "application/o/{}/.well-known/openid-configuration",
                    self.provider
                )
                .to_lowercase() // The provider is probably uppercase, but the endpoint expects lowercase
                .as_str(),
            )
            // If the well-known URL can't be constructed, the app can't run
            .expect("Could not construct Authentik well-known URL. Check your provider path.")
    }
}

#[derive(Deserialize, Debug)]
struct PostgresConfig {
    host: String,
    #[serde(default = "ConfigDefaults::postgres_port")]
    port: u16,
    #[serde(default = "ConfigDefaults::postgres_dbname")]
    db_name: String,
    user: String,
    password: String,
}

impl PostgresConfig {
    fn connection_string(&self) -> String {
        let host = &self.host;
        let port = &self.port;
        let db_name = &self.db_name;
        let user = &self.user;
        let pwd = &self.password;

        format!("postgres://{user}:{pwd}@{host}:{port}/{db_name}")
    }
}

/* This largely holds our Authentik information */
pub static CONFIG: OnceLock<SynalpheusConfig> = OnceLock::new();

/* Database connection */
pub static DATABASE: OnceLock<DatabaseConnection> = OnceLock::new();

#[tokio::main]
#[instrument]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().init();

    event!(Level::INFO, "Starting Synalpheus server");

    CONFIG
        .set(SynalpheusConfig::new())
        .expect("Failed to set Synalpheus config");

    /* CONFIG is guaranteed to be Some at this point */
    let config = CONFIG.get().unwrap();

    event!(Level::INFO, "Connecting to database");
    let db = Database::connect(config.postgres.connection_string())
        .await
        .expect("Could not connect to database");

    event!(Level::INFO, "Checking for pending migrations");
    Migrator::up(&db, None).await.map_err(InternalServerError)?;

    DATABASE.set(db).unwrap();

    event!(Level::INFO, "Creating application");
    let app = application::create_app();

    // If port is not specified, run on 80.
    // url::Url's port methods will probably return a None in our default cases
    let port = config.port;

    Server::new(TcpListener::bind(format!("0.0.0.0:{port}")))
        .name("synalpheus")
        .run(app)
        .await
        .map_err(InternalServerError)
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
        rename(deserialize = "meta_icon_url")
    )]
    icon: String,
    #[serde(rename(deserialize = "meta_description"))]
    description: String,
    meta_publisher: String,
    policy_engine_mode: String,
    group: String,
    meta_hide: bool,
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

/* Holds the list of applications for the user */
struct AppList {
    apps: Vec<AppCard>,
}

impl AppList {
    fn new() -> AppList {
        AppList { apps: Vec::new() }
    }

    #[instrument(skip_all)]
    fn add_authentik_apps(&mut self, auth_apps: AppResponse) {
        let config = CONFIG.get().unwrap();
        self.apps.append(
            &mut auth_apps
                .results
                .into_iter()
                /* Let's not include this app in the application list */
                .filter(|app| app.name.to_lowercase() != config.authentik.provider.to_lowercase())
                /* Follow Authentik's behavior of hiding apps with a launch URL of blank://blank */
                .filter(|app| app.launch_url.to_lowercase() != "blank://blank")
                /* Observe Authentik's dashboard display flag */
                .filter(|app| !app.meta_hide)
                .map(|a| a.into())
                .collect(),
        );
    }

    async fn add_local_apps(&mut self, groups: &Vec<String>) -> Result<impl IntoResponse> {
        /* local applications */
        let db = DATABASE.get().unwrap();
        self.apps.append(
            &mut LocalApp::Entity::find()
                .filter(
                    // Same behavior as Authentik: Limit to apps in groups the user belongs to, or are not in a group
                    Condition::any()
                        .add(LocalApp::COLUMN.group.is_in(groups))
                        .add(LocalApp::COLUMN.group.eq("")),
                )
                .all(db)
                .await
                .map_err(InternalServerError)?
                .into_iter()
                .map(|a| a.into())
                .collect(),
        );
        Ok(())
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

/* Not only is the meta_icon_url field nullable, but it's also a relative path on Authentik's domain.
 * Here we handle null values and also convert it to an absolute path so we can use them.
 * Fortunately we know this field is always going to be a string */
fn deserde_icon_url<'de, D>(de: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    /* This will be set when this is called for real, but not in tests.
     * Not sure this is actually helpful but can't hurt.
     */
    let config = cfg_select! {
        test => CONFIG.get_or_init(SynalpheusConfig::new),
            _ => CONFIG.get().unwrap()
    };
    let authentik_url = config.authentik.url.clone();

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

    /* A helper function that mocks a response from Authentik, not a test itself */
    fn load_sample_apps_response() -> Result<AppResponse, serde_json::Error> {
        let test_data = std::fs::read_to_string("test_data/get-applications-response.json")
            .expect("Unable to read test data file");
        serde_json::from_str::<AppResponse>(&test_data)
    }

    /* Actual tests begin here */

    /* Can we deserialize a user's GET response from Authentik's core/applications endpoint?  */
    #[test]
    fn can_parse_applications_response() {
        let response = load_sample_apps_response();
        assert!(response.is_ok())
    }

    /* Can we convert the Authentik response to a list of apps correctly? */
    #[test]
    fn can_collect_authentik_apps() {
        let mut applications = AppList::new();
        let response = load_sample_apps_response().unwrap();
        applications.add_authentik_apps(response);
        /* Eight apps in the data, minus:
         * - one with a matching provider name
         * - one with meta_hide = True
         * - one with url "blank://blank"  */
        assert_eq!(applications.apps.len(), 5)
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

        let config = CONFIG.get_or_init(SynalpheusConfig::new);
        let control = IconURLTester {
            icon: format!("{}/test.png", config.authentik.url),
            null_icon: "".to_string(),
        };

        let result: IconURLTester = serde_json::from_str(data).unwrap();

        assert_eq!(control, result)
    }
}

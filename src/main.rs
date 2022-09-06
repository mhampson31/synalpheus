use poem::{
    get, handler,
    listener::TcpListener,
    middleware::Tracing,
    session::{CookieConfig, CookieSession, Session},
    web::Path,
    EndpointExt, Route, Server,
};

#[handler]
async fn hello(Path(name): Path<String>, session: &Session) -> String {
    session.set("name", &name);
    format!("hello: {}", name)
}

#[handler]
async fn root(session: &Session) -> String {
    match session.get::<String>("name") {
        Some(name) => format!("Thou art {name}"),
        None => "Do I know you?".to_string(),
    }
}

#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var("RUST_LOG", "poem=debug");
    }
    tracing_subscriber::fmt::init();

    let app = Route::new()
        .at("/", get(root))
        .at("/hello/:name", get(hello))
        .with(Tracing)
        .with(CookieSession::new(CookieConfig::default().secure(false)));

    Server::new(TcpListener::bind("127.0.0.1:8080"))
        .name("hello-world")
        .run(app)
        .await
}

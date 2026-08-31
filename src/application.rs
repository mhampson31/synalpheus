use poem::{
    Endpoint, EndpointExt, IntoResponse, Route,
    endpoint::{StaticFileEndpoint, StaticFilesEndpoint},
    error::NotFoundError,
    get,
    http::StatusCode,
    middleware::{CatchPanic, Csrf, Tracing},
    session::{CookieConfig, CookieSession},
    web::Html,
};

use tera::Context;

use crate::{CONFIG, SynalpheusConfig, TEMPLATES, middleware, routes};

/* This creates our actual application. We call this out into a seperate function so
 * we can build a nearly-identical app for our testing.
 * The main difference will be in the session types, which we do not configure here, since test
 * functions will not use Redis. */
pub fn create_app() -> impl Endpoint {
    let config = CONFIG.get_or_init(|| SynalpheusConfig::new());
    let redirect_path = config.authentik.redirect.clone();
    Route::new()
        // static files
        .at(
            "static/css/output.css",
            StaticFileEndpoint::new("assets/css/output.css"),
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
        .with(CookieSession::new(CookieConfig::default()))
}

async fn four_oh_four(_: NotFoundError) -> impl IntoResponse {
    let response = TEMPLATES
        .render("404.html", &Context::new())
        .expect("Template failure");

    Html(response)
        .into_response()
        .with_status(StatusCode::NOT_FOUND)
}

//! An example showing how to use Auth0 (https://auth0.com/) together with
//! Rocket (https://rocket.rs) for managing user logins in Rust.
//!
//! In this simple example, sessions are represented as random UUIDv4 keys
//! mapping to email addresses. The session keys are stored as encrypted
//! cookies on the client.
//!
//! There are a number of things to be aware of before using this approach
//! in a production environment:
//!
//!   1. The encryption key for the cookies in this example is stored in
//!      the source code so that a single file suffices for the example.
//!      A real application would use a key in a Rocket.toml file and
//!      never check it into version control.
//!   2. The SessionMap is vulnerable to DoS. In a real application you
//!      should also include a timestamp and implement expiration or
//!      some other mechanism to prevent the SessionMap from growing
//!      without end.
//!   3. This code depends on a non-tagged version of Rocket (git
//!      rev "b8ba7b8") because encrypted cookies aren't supported
//!      in a released version at the time of this writing. By the
//!      time someone else might use this code, Rocket 0.3 may be
//!      released and should include this functionality.

#![feature(plugin, custom_derive)]
#![plugin(rocket_codegen)]

extern crate hyper;
extern crate hyper_native_tls;
extern crate jsonwebtoken as jwt;
#[macro_use]
extern crate log;
extern crate rocket;
extern crate rocket_contrib;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate uuid;

use std::collections::HashMap;
use std::io::Read;
use std::sync::RwLock;
use std::time::Duration;

use hyper::client::{Client, Response};
use hyper::header::ContentType;
use hyper::net::HttpsConnector;
use hyper_native_tls::NativeTlsClient;
use jwt::{encode, decode, Header, Algorithm, Validation};
use rocket::Outcome;
use rocket::State;
use rocket::config::{self, ConfigError};
use rocket::fairing::AdHoc;
use rocket::http::{Cookie, Cookies, Status};
use rocket::response::{Redirect, Flash};
use rocket::request::{self, Form, FlashMessage, FromRequest, Request};
use rocket_contrib::Template;
use uuid::Uuid;

/// Maps session keys to email addresses.
#[derive(Debug)]
struct SessionMap(RwLock<HashMap<String, String>>);

/// For the state of the application, including the client secrets.
struct AppSettings {
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    auth0_domain: String,
}

#[derive(Debug)]
struct Email(String);

/// Represents the access_code query string auth0 sends in a callback.
#[derive(FromForm)]
struct Code {
    code: String,
}

/// Represents a request for token_id retrieval.
#[derive(Debug, Serialize)]
struct TokenRequest<'r> {
    grant_type: &'r str,
    client_id: &'r str,
    client_secret: &'r str,
    code: &'r str,
    redirect_uri: &'r str,
}

/// Represents a reponse from token_id retrieval.
#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: u32,
    id_token: String,
    token_type: String,
}

/// Represents the structure of the token. There's only one field we care about.
#[derive(Debug, Deserialize)]
struct Token {
    email: String,
}

impl<'a, 'r> FromRequest<'a, 'r> for Email {
    type Error = ();

    fn from_request(request: &'a Request<'r>) -> request::Outcome<Email, ()> {
        let session_id: Option<String> = request.cookies()
            .get_private("session")
            .and_then(|cookie| cookie.value().parse().ok());

        match session_id {
            None => Outcome::Forward(()),
            Some(session_id) => {
                let session_map_state = State::<SessionMap>::from_request(request)
                    .unwrap();
                let session_map = session_map_state.0.read().unwrap();

                match session_map.get(&session_id) {
                    Some(email) => Outcome::Success(Email(email.clone())),
                    None => Outcome::Forward(())
                }
            }
        }
    }
}

fn random_session_id() -> String {
    Uuid::new_v4().simple().to_string()
}

#[get("/login?<code>")]
fn login_code(code: Code,
              hyper_client: State<Client>,
              settings: State<AppSettings>) -> Result<String, Status> {
    // There may be a better way to post this.
    let data = TokenRequest {
        grant_type: "authorization_code",
        client_id: &settings.client_id,
        client_secret: &settings.client_secret,
        code: &code.code,
        redirect_uri: &settings.redirect_uri,
    };

    // Now that we have a request, attempt to retrieve the token and decode.
    // This is a multi-step process with lots of opportunity for failure so
    // we wrap it in a closure and use `?`.
    let retrieve_id = || {
        let body: String = serde_json::to_string(&data).or(Err("json decode"))?;
        let mut res = hyper_client.post(&format!("https://{}/oauth/token", settings.auth0_domain))
            .body(&body)
            .header(ContentType::json())
            .send()
            .or(Err("sending"))?;
        if !(res.status == hyper::Ok) {
             return Err("bad response");
        }
        let mut buffer = String::new();
        res.read_to_string(&mut buffer).or(Err("reading buffer"))?;
        let token_response = serde_json::from_str::<TokenResponse>(&buffer)
                             .or(Err("json format"))?;
        // Todo: Use a better library for this.
        let token = decode::<Token>(&token_response.id_token,
                                     // Auth0 uses the client secret to sign its tokens.
                                     &settings.client_secret.as_bytes(),
                                     &Validation::default()).or(Err("decoding token"))?;
        Ok(token.claims.email)
    };
    // Todo: Log the error message.
    retrieve_id().or(Err(Status::BadGateway))
}

#[get("/")]
fn email_index(email: Email) -> String {
    format!("You are logged in as {}", email.0)
}

/// Called when a user doesn't have a valid cookie for session id.
/// Generates a new session id, stores it, and gives it to them.
#[get("/", rank = 2)]
fn index(settings: State<AppSettings>) -> Template {
    let mut context = HashMap::new();
    context.insert("client_id", &settings.client_id);
    context.insert("domain", &settings.auth0_domain);
    context.insert("callback", &settings.redirect_uri);

    Template::render("login", &context)
}


fn main() {
    let sessions = SessionMap(RwLock::new(HashMap::new()));
    let ssl = NativeTlsClient::new().unwrap();
    let connector = HttpsConnector::new(ssl);
    let mut hyper_client = Client::with_connector(connector);
    hyper_client.set_read_timeout(Some(Duration::from_secs(60)));

    rocket::ignite()
        .attach(Template::fairing())
        .mount("/", routes![email_index, index, login_code])
        .manage(sessions)
        .manage(hyper_client)
        .attach(AdHoc::on_attach(|rocket| {
            println!("Adding managed state for config...");
            let app_settings = AppSettings {
                client_id: String::from(rocket.config().get_str("client_id").unwrap()),
                client_secret: String::from(rocket.config().get_str("client_secret")
                                            .unwrap()),
                redirect_uri: String::from(rocket.config().get_str("redirect_uri")
                                           .unwrap()),
                auth0_domain: String::from(rocket.config().get_str("auth0_domain")
                                           .unwrap()),
            };
            Ok(rocket.manage(app_settings))
        }))
        .launch();
}

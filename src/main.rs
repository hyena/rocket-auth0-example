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

#![feature(plugin)]
#![plugin(rocket_codegen)]

extern crate rocket;
extern crate uuid;

use std::collections::HashMap;
use std::sync::RwLock;

use rocket::Outcome;
use rocket::State;
use rocket::config::{Config, Environment};
use rocket::http::{Cookie, Cookies};
use rocket::response::{Redirect, Flash};
use rocket::request::{self, Form, FlashMessage, FromRequest, Request};
use uuid::Uuid;


/// Maps session keys to email addresses.
#[derive(Debug)]
struct SessionMap(RwLock<HashMap<String, String>>);

#[derive(Debug)]
struct Email(String);

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

#[get("/")]
fn email_index(email: Email) -> String {
    format!("You are logged in as {}", email.0)
}

/// Called when a user doesn't have a valid cookie for session id.
/// Generates a new session id, stores it, and gives it to them.
#[get("/", rank = 2)]
fn index(mut cookies: Cookies, session_map: State<SessionMap>) -> &'static str {
    let new_session_id = random_session_id();
    {  // Minimize length of the write lifetime.
        let mut session_map = session_map.0.write().unwrap();
        session_map.insert(new_session_id.clone(), String::from("hyena@github.com"));
    }
    cookies.add_private(Cookie::new("session", new_session_id));

    "Inserted cookie. Reload the page."
}


fn main() {
    let sessions = SessionMap(RwLock::new(HashMap::new()));
    // In a real application be sure to generate and securely protect a real session key.
    let secret_key = "itlYmFR2vYKrOmFhupMIn/hyB6lYCCTXz4yaQX89XVg=";
    let config = Config::build(Environment::Development)
        .secret_key(secret_key)
        .unwrap();
    rocket::custom(config, true)
        .mount("/", routes![email_index, index])
        .manage(sessions)
        .launch();
}

use std::{fs::{OpenOptions, self}, path::Path, io::Write};

use rocket::{form::Form, http::Status, Shutdown, fs::FileServer, serde::json::serde_json};
use verify::{verify_id_token, Claims};
#[macro_use] extern crate rocket;

mod verify;

#[derive(FromForm)]
struct AuthedLink {
    id_token: String,
    link: String,
}

#[post(
    "/openlink",
    format = "multipart/form-data",
    data = "<data>"
)]
async fn openlink(data: Form<AuthedLink>) -> Result<Status, std::io::Error>{
    let claims = verify_id_token(&data.id_token, include_str!("client_id.txt")).await;
    if claims.is_some() {
        let claims = claims.unwrap();
        let saved_account: Claims = serde_json::from_str(
            fs::read_to_string("google_auth.json")
                .expect("Should have been able to read the file")
                .as_str(),
        ).expect("failed to parse google_auth.json");
        if claims.email_verified && claims.email == saved_account.email && claims.sub == saved_account.sub {
            open::that(data.link.clone())?;
            return Ok(Status::Ok);
        }
    }
    return Ok(Status::Forbidden);
}

#[derive(FromForm)]
struct Token {
    id_token: String,
}

fn create_or_open_file(path: &str) -> Result<std::fs::File, std::io::Error> {
    return OpenOptions::new()
        .write(true)
        .create(!Path::new(path).exists())
        .truncate(true)
        .open(path);
}

#[post(
    "/posttoken",
    format = "multipart/form-data",
    data = "<token>"
)]
async fn posttoken(token: Form<Token>, shutdown: Shutdown) -> Status {
    println!("checking token {}", token.id_token);
    let claims = verify_id_token(&token.id_token, include_str!("client_id.txt")).await;
    if claims.is_some() {
        let claims = claims.unwrap();
        if claims.email_verified {
        let mut auth_file = create_or_open_file("google_auth.json").expect("couldn't open auth file");
        auth_file.write_all(
            serde_json::to_string(&claims)
                .expect("could not write to users file")
                .as_bytes(),
        ).expect("couldn't write to auth file");
        shutdown.notify();
        return Status::Ok;
    }
    }
    return Status::Forbidden;
}

#[rocket::main]
async fn main() {
    if !Path::new("google_auth.json").exists() {
        open::that("https://linuxshare.chrissytopher.com/login.html").expect("couldn't open link");
        rocket::build()
            .mount(
                "/", FileServer::from("login")
            )
            .mount(
                "/",
                routes![
                    posttoken
                ],
            )
            .launch()
            .await.expect("login server failed");
    }
    let share_server_result = rocket::build()
        .mount(
            "/",
            FileServer::from("login"),
        )
        .mount(
            "/",
            routes![
                openlink,
            ],
        )
        .launch()
        .await;
    match share_server_result {
        Ok(_val) => {}
        Err(e) => println!("{e}"),
    }
}
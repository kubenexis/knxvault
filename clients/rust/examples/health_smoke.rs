//! W40-07: Rust client smoke example.
fn main() {
    let addr = std::env::var("KNXVAULT_ADDR").unwrap_or_else(|_| "http://127.0.0.1:8200".into());
    let url = format!("{addr}/health");
    let body = reqwest::blocking::get(&url)
        .expect("health request")
        .text()
        .expect("body");
    println!("{body}");
}
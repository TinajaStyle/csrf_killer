use super::structs::{Csrf, Data, Filters, Payload, RequestPart, RequestParts, Settings};
use indicatif::ProgressBar;
use regex::Regex;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::redirect::Policy;
use reqwest::{Client, Proxy, Response};
use serde_json::Value;
use std::collections::HashMap;
use std::error::Error;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::Mutex;

pub fn exit_with_err(msg: &str, err: Option<&dyn Error>) -> ! {
    let full_msg = match err {
        Some(err) => format!("{}: {}", msg, err),
        None => msg.to_string(),
    };

    log::error!("{}", full_msg);
    std::process::exit(1);
}

pub fn validate_tokens(tokens: &Vec<String>) -> HashMap<String, (String, Regex)> {
    let mut token_hashmap = HashMap::new();

    for token in tokens {
        let vt: Vec<&str> = token.split("==").collect();
        if vt.len() != 3 {
            exit_with_err(
                &format!("Invalid token struct: {}, must be == separate", token),
                None,
            );
        }
        token_hashmap.insert(
            vt.first().unwrap().to_string(),
            (
                vt.get(1).unwrap().to_string(),
                Regex::new(vt.get(2).unwrap()).unwrap(),
            ),
        );
    }
    token_hashmap
}

pub fn validate_headers(headers: &Vec<String>) -> HeaderMap {
    let mut header_map = HeaderMap::new();

    for header in headers {
        let pair: Vec<&str> = header.split(':').collect();
        if pair.len() != 2 {
            exit_with_err(
                format!("Invalid header: {}, must be : separate", header).as_str(),
                None,
            );
        }
        header_map.insert(
            HeaderName::from_str(pair.first().unwrap()).unwrap(),
            HeaderValue::from_str(pair.get(1).unwrap()).unwrap(),
        );
    }
    header_map
}

pub fn validate_form(data: &str) -> Option<Data> {
    let re = Regex::new(r"^([^=&]+=[^=&]+)(?:&[^=&]+=[^=&]+)*$").unwrap();

    if !re.is_match(data) {
        exit_with_err("Invalid format of form data", None);
    };

    let spliting = data.split('&');

    let mut form_hashmap = HashMap::new();

    for field in spliting {
        let pair: Vec<&str> = field.split('=').collect();
        form_hashmap.insert(
            pair.first().unwrap().to_string(),
            pair.get(1).unwrap().to_string(),
        );
    }

    if form_hashmap.is_empty() {
        return None;
    }
    Some(Data::Form(form_hashmap))
}

pub async fn get_lines(path: &str) -> (Arc<Payload>, u64) {
    let file = File::open(path)
        .await
        .unwrap_or_else(|err| exit_with_err("Can't open the wordlist", Some(&err)));

    let mut reader = BufReader::new(file).lines();
    let mut count = 0_u64;
    while reader.next_line().await.unwrap().is_some() {
        count += 1
    }

    let file = File::open(path)
        .await
        .unwrap_or_else(|err| exit_with_err("Can't open the wordlist", Some(&err)));

    (
        Arc::new(Payload::Lines(Mutex::new(BufReader::new(file).lines()))),
        count,
    )
}

pub fn create_client(settings: Arc<Settings>) -> Client {
    let mut builder = reqwest::Client::builder();

    if settings.options.store_cookies {
        builder = builder.cookie_store(true);
    }
    if let Some(headers) = &settings.options.headers {
        builder = builder.default_headers(headers.clone());
    }

    if !settings.options.redirects {
        builder = builder.redirect(Policy::none())
    }

    if let Some(proxy) = &settings.options.proxy {
        builder = builder
            .proxy(
                Proxy::http(proxy).unwrap_or_else(|err| exit_with_err("Invalid proxy", Some(&err))),
            )
            .proxy(
                Proxy::https(proxy)
                    .unwrap_or_else(|err| exit_with_err("Invalid proxy", Some(&err))),
            )
    }

    builder = builder.timeout(Duration::from_secs_f32(settings.options.timeout));

    builder.build().expect("Faild to build Client")
}

pub fn filter_tokens(csrf: &Csrf, text: &str) -> Option<RequestParts> {
    let mut tokens = RequestParts::new();

    for (name, (position, re)) in csrf.tokens.iter() {
        let matched = re.captures(text)?.iter().last()?.as_ref()?.as_str();

        let token = match position.as_str() {
            "form" => {
                let mut hash_map = HashMap::new();
                hash_map.insert(name.to_string(), matched.to_string());
                RequestPart::Data(Data::Form(hash_map))
            }
            "json" => {
                let json_str = format!("{{\"{}\": \"{}\"}}", name, matched);
                RequestPart::Data(Data::Json(serde_json::from_str(&json_str).unwrap()))
            }
            "query" => RequestPart::Query(name.to_string(), matched.to_string()),
            "header" => RequestPart::Header(name.to_string(), matched.to_string()),
            "cookie" => {
                let cookie = format!("{}={}", name, matched);
                RequestPart::Cookie(cookie)
            }
            _ => panic!("Invalid token position"),
        };
        tokens.add(token);
    }
    Some(tokens)
}

pub async fn log_response(
    response: Response,
    filters: &Filters,
    payload: String,
    no: u32,
    pb: &ProgressBar,
) {
    let status_code = response.status().as_u16();
    let content_length = response.content_length().unwrap_or(0);
    let text = response.text().await.unwrap_or(String::new());
    let words = text.split_whitespace().count() as u64;
    let chars = text.chars().count() as u64;

    let fl = filters.status.map_or(false, |f| f == status_code)
        || filters.length.map_or(false, |f| f == content_length)
        || filters.words.map_or(false, |f| f == words)
        || filters.chars.map_or(false, |f| f == chars);

    if !fl {
        pb.suspend(|| {
            println!(
                "{:<10} {:<15} {:<15} {:<15} {:<15} {:<15}",
                no, status_code, content_length, words, chars, payload
            );
        });
    }
}

// https://stackoverflow.com/questions/47070876/how-can-i-merge-two-json-objects-with-rust
pub fn merge_json(a: &mut Value, b: Value) {
    match (a, b) {
        (a @ &mut Value::Object(_), Value::Object(b)) => {
            let a = a.as_object_mut().unwrap();
            for (k, v) in b {
                merge_json(a.entry(k).or_insert(Value::Null), v);
            }
        }
        (a, b) => *a = b,
    }
}

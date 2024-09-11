use super::cli::Args;
use super::helper::merge_json;
use indicatif::ProgressBar;
use regex::Regex;
use reqwest::header::HeaderMap;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::atomic::AtomicU32;
use tokio::fs::File;
use tokio::io::BufReader;
use tokio::sync::Mutex;

pub struct Csrf {
    pub url: String,
    pub tokens: HashMap<String, (String, Regex)>,
}

pub struct Target {
    pub url: String,
    pub method: String,
    pub data: Option<Data>,
}

pub struct Filters {
    pub status: Option<u16>,
    pub length: Option<u64>,
    pub words: Option<u64>,
    pub chars: Option<u64>,
}

pub struct RequestOptions {
    pub headers: Option<HeaderMap>,
    pub store_cookies: bool,
    pub redirects: bool,
    pub proxy: Option<String>,
    pub timeout: f32,
}

pub struct Settings {
    pub csrf: Csrf,
    pub target: Target,
    pub concurrence: u16,
    pub brute_force: bool,
    pub wordlist: Option<String>,
    pub options: RequestOptions,
    pub filters: Filters,
}

impl Settings {
    pub fn from_args(
        args: &Args,
        tokens: HashMap<String, (String, Regex)>,
        data: Option<Data>,
        headers: Option<HeaderMap>,
    ) -> Self {
        Self {
            target: Target {
                url: args.url.clone(),
                method: args.method.clone(),
                data,
            },
            csrf: Csrf {
                url: args.csrf_url.clone(),
                tokens,
            },
            concurrence: args.concurrence,
            brute_force: args.brute_force,
            wordlist: args.wordlist.clone(),
            options: RequestOptions {
                store_cookies: args.store_cookies,
                headers,
                redirects: args.no_redirects,
                proxy: args.proxy.clone(),
                timeout: args.timeout,
            },
            filters: Filters {
                status: args.no_status,
                length: args.no_length,
                words: args.no_words,
                chars: args.no_chars,
            },
        }
    }
}

pub struct Progress {
    pub pb: ProgressBar,
    pub no_req: AtomicU32,
    pub no_err: AtomicU32,
}

pub enum Payload {
    Lines(Mutex<tokio::io::Lines<BufReader<File>>>),
    Future,
}

pub enum Data {
    Form(HashMap<String, String>),
    Json(Value),
}

pub enum RequestPart {
    Header(String, String),
    Cookie(String),
    Query(String, String),
    Data(Data),
}

pub struct RequestParts {
    pub values: Vec<RequestPart>,
}

impl RequestParts {
    pub fn new() -> Self {
        Self { values: Vec::new() }
    }

    pub fn add(&mut self, token: RequestPart) {
        self.values.push(token);
    }

    pub fn extend(&mut self, rp: RequestParts) {
        self.values.extend(rp.values);
    }

    fn join_part(a: RequestPart, b: RequestPart) -> RequestPart {
        match (a, b) {
            (
                RequestPart::Data(Data::Form(ref mut form_a)),
                RequestPart::Data(Data::Form(form_b)),
            ) => {
                form_a.extend(form_b);
                RequestPart::Data(Data::Form(form_a.clone()))
            }
            (
                RequestPart::Data(Data::Json(ref mut json_a)),
                RequestPart::Data(Data::Json(json_b)),
            ) => {
                merge_json(json_a, json_b);
                RequestPart::Data(Data::Json(json_a.clone()))
            }
            (RequestPart::Cookie(cookie_a), RequestPart::Cookie(cookie_b)) => {
                RequestPart::Cookie(format!("{}; {}", cookie_a, cookie_b))
            }
            (a, _) => a,
        }
    }

    pub fn join_parts(&mut self) {
        let mut new_values = RequestParts::new();

        while let Some(part) = self.values.pop() {
            if matches!(part, RequestPart::Query(..) | RequestPart::Header(..)) {
                new_values.add(part);
                continue;
            }

            if let Some(pos) = new_values
                .values
                .iter()
                .position(|x| std::mem::discriminant(x) == std::mem::discriminant(&part))
            {
                let joined = RequestParts::join_part(new_values.values.remove(pos), part);
                new_values.add(joined)
            } else {
                new_values.add(part)
            }
        }

        *self = new_values;
    }
}

use super::cli::Args;
use super::helper::merge_json;
use indicatif::ProgressBar;
use regex::Regex;
use reqwest::header::HeaderMap;
use serde_json::Value;
use std::borrow::Cow;
use std::collections::HashMap;
use std::error::Error;
use std::fmt::Display;
use std::sync::atomic::AtomicUsize;

pub struct Csrf {
    pub url: String,
    pub tokens: HashMap<String, (String, Regex)>,
}

pub struct Target {
    pub url: String,
    pub method: String,
    pub data: Option<Data>,
}

pub struct Modes {
    pub brute_force: bool,
    pub wordlist: Option<String>,
    pub upload_files: bool,
    pub file_paths: Option<String>,
    pub field_name: Option<String>,
}

pub struct Filters {
    pub status: Option<u16>,
    pub length: Option<u64>,
    pub lines: Option<usize>,
    pub words: Option<usize>,
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
    pub modes: Modes,
    pub concurrence: u16,
    pub delay: f32,
    pub repeat: u16,
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
            modes: Modes {
                brute_force: args.brute_force,
                wordlist: args.wordlist.clone(),
                upload_files: args.upload_files,
                file_paths: args.file_paths.clone(),
                field_name: args.field_name.clone(),
            },
            concurrence: args.concurrence,
            delay: args.delay,
            repeat: args.repeat,
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
                lines: args.no_lines,
            },
        }
    }
}

pub struct Progress {
    pub pb: ProgressBar,
    pub no_req: AtomicUsize,
    pub no_err: AtomicUsize,
}

pub enum Payload<'a> {
    Line(&'a str),
    Upload(&'a str, &'a str),
}

pub enum Data {
    Form(HashMap<String, String>),
    Json(Value),
    PartText(HashMap<String, String>),
    File(String, String, String, Vec<u8>),
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

impl Default for RequestParts {
    fn default() -> Self {
        RequestParts::new()
    }
}

impl RequestParts {
    pub fn new() -> Self {
        Self { values: Vec::new() }
    }

    pub fn add(&mut self, token: RequestPart) {
        self.values.push(token);
    }

    pub fn add_fuzz_data(&mut self, data: Option<&Data>, line: &str) {
        match data {
            Some(Data::Form(form_data)) => {
                let form_data = RequestParts::replace_fuzz_hashmap(form_data, line);
                self.add(RequestPart::Data(Data::Form(form_data)))
            }
            Some(Data::Json(json_data)) => {
                let json_str = json_data.clone().to_string().replace("FUZZ", line);
                self.add(RequestPart::Data(Data::Json(
                    serde_json::from_str(&json_str).unwrap(),
                )))
            }
            Some(Data::PartText(data)) => {
                let data = RequestParts::replace_fuzz_hashmap(data, line);
                self.add(RequestPart::Data(Data::PartText(data)))
            }
            _ => (),
        };
    }

    fn replace_fuzz_hashmap(old: &HashMap<String, String>, line: &str) -> HashMap<String, String> {
        let mut new = old.clone();
        new.iter_mut()
            .for_each(|(_, v)| *v = v.replace("FUZZ", line));
        new
    }

    pub fn extend(&mut self, rp: RequestParts) {
        self.values.extend(rp.values);
    }

    fn join_part(a: RequestPart, b: RequestPart) -> RequestPart {
        match (a, b) {
            (RequestPart::Data(Data::Form(mut form_a)), RequestPart::Data(Data::Form(form_b))) => {
                form_a.extend(form_b);
                RequestPart::Data(Data::Form(form_a))
            }
            (RequestPart::Data(Data::Json(mut json_a)), RequestPart::Data(Data::Json(json_b))) => {
                merge_json(&mut json_a, json_b);
                RequestPart::Data(Data::Json(json_a))
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
            // this don't need to join:
            // Query | PartText | File: the RequestBuilder can unite them
            // Header: unless they are in the RequestBuilder can unite without overwrite
            if matches!(
                part,
                RequestPart::Query(..)
                    | RequestPart::Header(..)
                    | RequestPart::Data(Data::PartText(..))
                    | RequestPart::Data(Data::File(..))
            ) {
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

/// Unrecoverable error if matched program will stop
#[derive(Debug)]
pub struct KillerError {
    pub detail: Cow<'static, str>,
}

impl Display for KillerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", &self.detail)
    }
}

impl Error for KillerError {}

/// Union between KillerError and reqwest::Error
pub enum ErrorEnum {
    #[allow(dead_code)]
    ReqwestError(reqwest::Error),
    KillerError(KillerError),
}

impl From<reqwest::Error> for ErrorEnum {
    fn from(value: reqwest::Error) -> Self {
        Self::ReqwestError(value)
    }
}

impl From<KillerError> for ErrorEnum {
    fn from(value: KillerError) -> Self {
        Self::KillerError(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_add_request_parts() {
        let mut parts = RequestParts::new();
        parts.add(RequestPart::Header(
            "Content-Type".to_string(),
            "application/json".to_string(),
        ));
        parts.add(RequestPart::Cookie("session_id".to_string()));

        assert_eq!(parts.values.len(), 2);
        match &parts.values[0] {
            RequestPart::Header(key, value) => {
                assert_eq!(key, "Content-Type");
                assert_eq!(value, "application/json");
            }
            _ => panic!("Expected header"),
        }
        match &parts.values[1] {
            RequestPart::Cookie(cookie) => assert_eq!(cookie, "session_id"),
            _ => panic!("Expected cookie"),
        }
    }

    #[test]
    fn test_extend_request_parts() {
        let mut parts1 = RequestParts::new();
        parts1.add(RequestPart::Header(
            "Content-Type".to_string(),
            "application/json".to_string(),
        ));

        let mut parts2 = RequestParts::new();
        parts2.add(RequestPart::Cookie("session_id".to_string()));

        parts1.extend(parts2);

        assert_eq!(parts1.values.len(), 2);
    }

    #[test]
    fn test_merge_form_data() {
        let mut form_a = HashMap::new();
        form_a.insert("username".to_string(), "user1".to_string());

        let mut form_b = HashMap::new();
        form_b.insert("password".to_string(), "pass123".to_string());

        let mut parts = RequestParts::new();
        parts.add(RequestPart::Data(Data::Form(form_a)));

        let mut other_parts = RequestParts::new();
        other_parts.add(RequestPart::Data(Data::Form(form_b)));

        parts.extend(other_parts);
        parts.join_parts();

        match &parts.values[0] {
            RequestPart::Data(Data::Form(form)) => {
                assert_eq!(form.get("username"), Some(&"user1".to_string()));
                assert_eq!(form.get("password"), Some(&"pass123".to_string()));
            }
            _ => panic!("Expected form data"),
        }
    }

    #[test]
    fn test_merge_json_data() {
        let json_a: Value = json!({"key1": "value1"});
        let json_b: Value = json!({"key2": "value2"});

        let mut parts = RequestParts::new();
        parts.add(RequestPart::Data(Data::Json(json_a)));

        let mut other_parts = RequestParts::new();
        other_parts.add(RequestPart::Data(Data::Json(json_b)));

        parts.extend(other_parts);
        parts.join_parts();

        match &parts.values[0] {
            RequestPart::Data(Data::Json(json)) => {
                assert_eq!(json["key1"], "value1");
                assert_eq!(json["key2"], "value2");
            }
            _ => panic!("Expected JSON data"),
        }
    }

    #[test]
    fn test_merge_cookies() {
        let mut parts = RequestParts::new();
        parts.add(RequestPart::Cookie("cookie1=value1".to_string()));
        parts.add(RequestPart::Cookie("cookie2=value2".to_string()));

        parts.join_parts();

        assert_eq!(parts.values.len(), 1);
        match &parts.values[0] {
            RequestPart::Cookie(cookies) => {
                assert_eq!(cookies, "cookie2=value2; cookie1=value1");
            }
            _ => panic!("Expected merged cookies"),
        }
    }
}

use super::helper::{validate_form, validate_headers, validate_tokens};
use super::structs::{Data, KillerError, Settings};
use clap::builder::styling;
use clap::{crate_authors, crate_name, crate_version, ArgAction, ArgGroup, Parser};

const STYLES: styling::Styles = styling::Styles::styled()
    .header(styling::AnsiColor::Blue.on_default().bold())
    .usage(styling::AnsiColor::Green.on_default().bold())
    .literal(styling::AnsiColor::Cyan.on_default().bold());

#[derive(Parser, Debug)]
#[command(
    author = crate_authors!(),
    name = crate_name!(),
    about = "delete csrf",
    version = crate_version!(),
    styles(STYLES),
    group(ArgGroup::new("modes").args(&["brute_force", "upload_files"])),
    group(ArgGroup::new("filters").args(&["no_status", "no_length", "no_words", "no_chars"])),
    long_about = None
)]
pub struct Args {
    #[arg(
        short = 'u',
        long = "url",
        required = true,
        help_heading = "Target",
        help = "Target url"
    )]
    pub url: String,

    #[arg(
        short = 'c',
        long = "csrf-url",
        required = true,
        help_heading = "CSRF",
        help = "Url to take the csrf tokens"
    )]
    pub csrf_url: String,

    #[arg(
        short = 't',
        long = "token",
        required = true,
        help_heading = "CSRF",
        help = "Token 'token_name==where_send==regex' to filter and add. \
                Can accept multiples call. The token can be send in [form, json, query, header, cookie]"
    )]
    pub tokens: Vec<String>,

    #[arg(
        short = 'X',
        long = "method",
        default_value = "post",
        value_parser = ["get", "post", "put", "delete"],
        help_heading = "Target",
        help = "request method"
    )]
    pub method: String,

    #[arg(
        long = "brute-force",
        requires = "wordlist",
        help_heading = "Mode",
        help = "Brute force the FUZZ keyword"
    )]
    pub brute_force: bool,

    #[arg(
        short = 'w',
        long = "wordlist",
        requires = "brute_force",
        help_heading = "Brute Force Options",
        help = "Path to the wordlist"
    )]
    pub wordlist: Option<String>,

    #[arg(
        long = "upload-files",
        requires = "file_paths",
        requires = "field_name",
        conflicts_with = "data_post",
        help_heading = "Mode",
        help = "Upload files continuously"
    )]
    pub upload_files: bool,

    #[arg(
        short = 'f',
        long = "file-paths",
        requires = "upload_files",
        help_heading = "Upload File Options",
        help = "Path to the file that contains the paths of the files to upload"
    )]
    pub file_paths: Option<String>,

    #[arg(
        long = "field-name",
        requires = "upload_files",
        help_heading = "Upload File Options",
        help = "The name of the field where the files will be sent"
    )]
    pub field_name: Option<String>,

    #[arg(
        short = 'T',
        long = "concurrence",
        default_value = "10",
        help_heading = "Performance",
        help = "Number of concurrence tasks"
    )]
    pub concurrence: u16,

    #[arg(
        long = "delay",
        default_value = "0.005",
        help_heading = "Performance",
        help = "Delay between requests"
    )]
    pub delay: f32,

    #[arg(
        long = "data-post",
        requires = "data_type",
        help_heading = "Target",
        help = "Data to tramite in post"
    )]
    pub data_post: Option<String>,

    #[arg(
        long = "data-type",
        value_parser = ["json", "form", "multipart"],
        help_heading = "Target",
        help = "The content type of the data post"
    )]
    pub data_type: Option<String>,

    #[arg(
        short = 'H',
        long = "headers",
        help_heading = "Request",
        help = "Headers 'Name:Value' to add"
    )]
    pub headers: Option<Vec<String>>,

    #[arg(
        long = "store-cookies",
        help_heading = "Request",
        help = "Store recived cookies in responses"
    )]
    pub store_cookies: bool,

    #[arg(
        short = 'R',
        long = "no-redirects",
        action = ArgAction::SetFalse,
        help_heading = "Request",
        help = "Not follow redirects"
    )]
    pub no_redirects: bool,

    #[arg(long = "proxy", help_heading = "Request", help = "Set an http proxy")]
    pub proxy: Option<String>,

    #[arg(
        short = 'o',
        long = "timeout",
        default_value = "5",
        help_heading = "Request",
        help = "Time to spend the request"
    )]
    pub timeout: f32,

    #[arg(
        long = "no-status",
        help_heading = "Filters",
        help = "Do not show status code"
    )]
    pub no_status: Option<u16>,

    #[arg(
        long = "no-length",
        help_heading = "Filters",
        help = "Do not show length"
    )]
    pub no_length: Option<u64>,

    #[arg(
        long = "no-words",
        help_heading = "Filters",
        help = "Do not show words"
    )]
    pub no_words: Option<u64>,

    #[arg(
        long = "no-chars",
        help_heading = "Filters",
        help = "Do not show chars"
    )]
    pub no_chars: Option<u64>,
}

impl Args {
    pub fn move_to_setting(self) -> Result<Settings, KillerError> {
        let mut found_fuzz = false;

        if self.url.contains("FUZZ") {
            found_fuzz = true;
        }
        // TODO fuzz in headers
        let headers = self.headers.as_ref().map(validate_headers).transpose()?;

        let tokens = validate_tokens(&self.tokens)?;

        let data = match (&self.data_post, &self.data_type) {
            (Some(data_post), Some(data_type)) => {
                for (pos, _) in tokens.values() {
                    if (pos == "json" || pos == "form" || pos == "multipart") && data_type != pos {
                        return Err(KillerError {
                            detail: "Can't send multiples data type in the same request ex: json and form",
                        });
                    }
                }

                if data_post.contains("FUZZ") {
                    found_fuzz = true;
                };

                if data_type == "form" {
                    Some(Data::Form(validate_form(data_post)?))
                } else if data_type == "json" {
                    Some(Data::Json(serde_json::from_str(data_post).map_err(
                        |err| KillerError {
                            detail: Box::leak(format!("Invalid json: {}", err).into_boxed_str()),
                        },
                    )?))
                } else if data_type == "multipart" {
                    Some(Data::PartText(validate_form(data_post)?))
                } else {
                    unreachable!()
                }
            }
            (_, _) => None,
        };

        if self.brute_force && !found_fuzz {
            return Err(KillerError {
                detail: "Mode brute force without FUZZ keyword",
            });
        }

        Ok(Settings::from_args(&self, tokens, data, headers))
    }
}

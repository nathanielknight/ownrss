use serde::Deserialize;
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use log::{debug, info};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    info!("Loading config from ownrss.toml");
    let config = AppConfig::from_file(Path::new("./ownrss.toml")).expect("Error loading config");
    let addr = config
        .address
        .parse::<SocketAddr>()
        .expect("Invalid address");
    info!(
        "Loading files from {}",
        config
            .files_directory
            .to_str()
            .expect("files_directory isn't a str?")
    );
    let files =
        load_files(&config.files_directory, &config.filename_salt).expect("Failed to parse files");

    let password_hashes: HashMap<String, String> = config
        .users
        .iter()
        .map(|u| (u.name.to_owned(), u.password_hash.to_owned()))
        .collect();

    let app = app::new(files, config.baseurl, password_hashes);

    info!("Servering OwnRss on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .expect("Error running server");
}

#[derive(Deserialize)]
struct AppConfig {
    files_directory: PathBuf,
    baseurl: String,
    address: String,
    users: Vec<User>,
    filename_salt: String,
}

#[derive(Deserialize)]
struct User {
    name: String,
    password_hash: String,
}

impl AppConfig {
    fn from_file(fname: &Path) -> io::Result<AppConfig> {
        let src = std::fs::read_to_string(fname)?;
        let config = toml::from_str(&src).expect("Error parsing config");
        Ok(config)
    }
}

mod app {
    use super::*;
    use axum::{
        extract::{Extension, Path},
        headers::{authorization::Basic, Authorization},
        http::StatusCode,
        response::Response,
        TypedHeader,
    };
    use std::sync::{Arc, Mutex};

    struct State {
        files: Files,
        baseurl: String,
        password_hashes: HashMap<String, String>,
    }

    type StateExtension = Extension<Arc<Mutex<State>>>;

    pub fn new(
        files: Files,
        baseurl: String,
        password_hashes: HashMap<String, String>,
    ) -> axum::Router {
        use axum::routing::get;
        use axum::Router;

        let appstate = State {
            files,
            baseurl,
            password_hashes,
        };

        Router::new()
            .route("/feed.xml", get(main_feed))
            .route("/file/:slug", get(get_file))
            .layer(Extension(Arc::new(Mutex::new(appstate))))
    }

    #[axum_macros::debug_handler]
    async fn main_feed(
        TypedHeader(basicauth): TypedHeader<Authorization<Basic>>,
        appstate: StateExtension,
    ) -> Result<Response<String>, (StatusCode, String)> {
        let mut statelock = appstate.lock().expect("Failed to lock app state");
        let state = &mut *statelock;

        let username = basicauth.username();
        let password = basicauth.password();

        let password_hash = state.password_hashes.get(username);
        let authenticated = match password_hash {
            Some(hash) => auth::check_password(password, hash),
            None => false,
        };

        if authenticated {
            let body = generate_feed(&state.files, &state.baseurl);
            Response::builder()
                .header("content-type", "application/xml; charset=utf-8")
                .body(body)
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("{}", e)))
        } else {
            Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body("Unauthorized".to_owned())
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("{}", e)))
        }
    }

    async fn get_file(
        Path(slug): Path<String>,
        appstate: StateExtension,
    ) -> Result<Vec<u8>, (StatusCode, &'static str)> {
        info!("Retrieving file for {}", slug);
        let mut statelock = appstate.lock().expect("Failed to lock app state");
        let state = &mut *statelock;
        let fileentry = state.files.get(&slug);

        if let Some(appfile) = fileentry {
            std::fs::read(&appfile.path)
                .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Failed to open file"))
        } else {
            Err((StatusCode::NOT_FOUND, "Not Found"))
        }
    }
}

#[derive(Debug)]
pub struct File {
    path: PathBuf,
    name: String,
    length: u64,
    slug: String,
    mimetype: String,
}

pub type Files = HashMap<String, File>;

fn load_files(dir: &PathBuf, salt: &str) -> io::Result<Files> {
    use std::fs::read_dir;

    let mut files: Files = HashMap::new();

    for entry_result in read_dir(dir)? {
        let entry = entry_result?;
        let path = entry.path();
        debug!(
            "Loading file: {}",
            &path.as_path().to_str().expect("Invalid filename")
        );
        let file = File::from_path(&path, salt)?;
        files.insert(file.slug.clone(), file);
    }
    Ok(files)
}

impl File {
    fn from_path(path: &PathBuf, salt: &str) -> io::Result<File> {
        let name = path
            .file_name()
            .unwrap_or_default()
            .to_os_string()
            .to_string_lossy()
            .into_owned();
        let file = std::fs::File::open(path)?;
        let metadata = file.metadata()?;
        let length = metadata.len();
        let mimetype = get_mimetype(path).unwrap_or_default();
        let slug = get_file_slug(&name, file, salt)?;
        let file = File {
            path: path.clone(),
            slug,
            length,
            mimetype,
            name,
        };
        Ok(file)
    }

    fn url_for(&self, baseurl: &str) -> String {
        format!("{}/file/{}", baseurl, self.slug)
    }
}

impl File {
    fn rss_item(&self, baseurl: &str) -> rss::Item {
        use rss::ItemBuilder;
        let title = self.name.clone();
        let guid = rss::Guid {
            value: self.slug.clone(),
            permalink: false,
        };
        let enclosure = rss::Enclosure {
            url: self.url_for(baseurl),
            length: self.length.to_string(),
            mime_type: self.mimetype.clone(),
        };
        ItemBuilder::default()
            .title(title)
            .guid(Some(guid))
            .enclosure(Some(enclosure))
            .build()
    }
}

fn get_mimetype(path: &Path) -> Option<String> {
    path.extension()?.to_str()?.parse().ok()
}

fn get_file_slug(name: &str, file: std::fs::File, salt: &str) -> io::Result<String> {
    use base64::engine::general_purpose::URL_SAFE;
    use base64::engine::Engine;
    use sha2::{Digest, Sha256};
    use std::io::{BufReader, Read};

    let mut bufread = BufReader::new(file);

    let digest = {
        let mut hasher: Sha256 = Sha256::new();
        hasher.update(salt);
        hasher.update(name);
        let mut buffer = [0; 2048];
        // Get the SHA2 hash of the first 2048 bytes of the file.
        let count = bufread.read(&mut buffer)?;
        if count < 2048 {
            debug!("Got only {} initial bytes for file slug instead of 2048", count);
        }
        hasher.update(buffer);
        hasher.finalize()
    };
    let slug = URL_SAFE.encode(digest);
    Ok(slug)
}

fn generate_feed(files: &Files, baseurl: &str) -> String {
    use rss::ChannelBuilder;

    let items = generate_items(files, baseurl);

    let channel = ChannelBuilder::default()
        .title("OwnRss".to_string())
        .link(baseurl.to_owned())
        .description("TODO".to_string())
        .generator(Some("OwnRss".to_string()))
        .items(items)
        .build();
    channel.to_string()
}

fn generate_items(files: &Files, baseurl: &str) -> Vec<rss::Item> {
    let mut files: Vec<&File> = files.values().collect();
    files.sort_by_key(|f| &f.name);
    files.iter().map(|f| f.rss_item(baseurl)).collect()
}

mod auth {
    use super::*;
    use scrypt::{
        password_hash::{PasswordHash, PasswordVerifier},
        Scrypt,
    };

    #[must_use]
    pub fn check_password(password: &str, hash: &str) -> bool {
        // let password_hash = Scrypt.hash_password(password, &salt)?.to_string();
        // Verify password against PHC string
        debug!("Checking password");
        let parsed_hash = match PasswordHash::new(hash) {
            Ok(hash) => hash,
            Err(_) => {
                debug!("Invalid password");
                return false
            }
        };
        let ok = Scrypt
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok();
        debug!("Done checking");
        ok
    }
}

use axum::{
    extract::{Query, State},
    http::{header, HeaderMap, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Json, Redirect, Response},
    routing::get,
    Router,
};
use axum_extra::extract::cookie::{Cookie, SameSite};
use dotenv::dotenv;
use oauth2::{
    basic::BasicClient, reqwest::async_http_client, AuthUrl, AuthorizationCode, ClientId,
    ClientSecret, CsrfToken, RedirectUrl, Scope, TokenUrl, TokenResponse,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{fmt, sync::Arc};
use dashmap::DashMap;
use tower_http::cors::CorsLayer;
use time::OffsetDateTime;

#[derive(Debug, Deserialize)]
struct AuthRequest {
    code: String,
    state: String,
}

#[derive(Debug, Deserialize)]
struct GoogleUserInfo {
    sub: String,
    email: String,
    name: String,
    picture: Option<String>,
}

// Struct to store user session data
#[derive(Debug, Clone, Deserialize, Serialize)]
struct UserSession {
    id: String,
    email: String,
    name: String,
    avatar: Option<String>,
    // skills: Vec<String>,
    // bio: String,
}

#[derive(Debug)]
enum AuthError {
    OAuth2(String),
    Reqwest(String),
    CookieParse(String),
    Unauthorized(String), 
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AuthError::OAuth2(e) => write!(f, "OAuth2 error: {}", e),
            AuthError::Reqwest(e) => write!(f, "Reqwest error: {}", e),
            AuthError::CookieParse(e) => write!(f, "Cookie parse error: {}", e),
            AuthError::Unauthorized(e) => write!(f, "Unauthorized: {}", e),
        }
    }
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let status = match self {
            AuthError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        let body = json!({ "error": self.to_string() });
        (status, Json(body)).into_response()
    }
}

// Application state to be shared across handlers
struct AppState {
    oauth_client: BasicClient,
    user_sessions: DashMap<String, UserSession>, 
}

#[tokio::main]
async fn main() {
    // dotenv().expect("Failed to load .env file");

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let google_client_id = dotenv::var("GOOGLE_CLIENT_ID")
        .expect("GOOGLE_CLIENT_ID must be set");
    let google_client_secret = dotenv::var("GOOGLE_CLIENT_SECRET")
        .expect("GOOGLE_CLIENT_SECRET must be set");
    let redirect_url = dotenv::var("REDIRECT_URL")
        .unwrap_or_else(|_| "http://localhost:8080/auth/google/callback".to_string());

    let client = BasicClient::new(
        ClientId::new(google_client_id),
        Some(ClientSecret::new(google_client_secret)),
        AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string()).unwrap(),
        Some(TokenUrl::new("https://oauth2.googleapis.com/token".to_string()).unwrap()),
    )
    .set_redirect_uri(RedirectUrl::new(redirect_url).unwrap());

    // Initialize the shared application state
    let app_state = Arc::new(AppState {
        oauth_client: client,
        user_sessions: DashMap::new(),
    });

    let frontend_url = dotenv::var("FRONTEND_URL")
        .unwrap_or_else(|_| "http://localhost:3000".to_string());

    let cors = CorsLayer::new()
    .allow_origin(frontend_url.parse::<HeaderValue>().unwrap())
    .allow_methods([Method::GET, Method::POST])
    .allow_headers([
        header::CONTENT_TYPE,
        header::AUTHORIZATION,
        header::ACCEPT,
    ])
    .allow_credentials(true)
    .expose_headers([header::SET_COOKIE]);

    let app = Router::new()
        .route("/", get(home))
        .route("/auth/google", get(login_with_google))
        .route("/auth/google/callback", get(google_oauth_callback))
        .route("/protected", get(protected))
        .route("/api/user", get(get_current_user))
        .route("/auth/signout", get(sign_out))
        .layer(cors)
        .with_state(app_state);

    // --- MODIFICATION HERE ---
    let port = dotenv::var("PORT")
        .unwrap_or_else(|_| "10000".to_string())
        .parse::<u16>()
        .expect("PORT must be a valid number");
    let addr = format!("0.0.0.0:{}", port);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    tracing::info!("Server running on http://{}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}

async fn home() -> Json<serde_json::Value> {
    Json(json!({
        "message": "Welcome to the Auth API",
        "endpoints": {
            "login": "/auth/google",
            "protected": "/protected",
            "user_info": "/api/user",
            "sign_out": "/auth/signout"
        }
    }))
}

async fn login_with_google(
    State(app_state): State<Arc<AppState>>, // Use AppState
) -> Result<Redirect, AuthError> {
    let (auth_url, csrf_token) = app_state.oauth_client // Access client from app_state
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .add_scope(Scope::new("openid".to_string()))
        .url();

    tracing::debug!("Generated CSRF token: {}", csrf_token.secret());
    Ok(Redirect::to(auth_url.as_str()))
}

async fn google_oauth_callback(
    State(app_state): State<Arc<AppState>>, // Use AppState
    Query(query): Query<AuthRequest>,
) -> Result<impl IntoResponse, AuthError> {
    tracing::debug!("Received state: {}", query.state);

    let code = AuthorizationCode::new(query.code);
    let token_response = app_state.oauth_client // Access client from app_state
        .exchange_code(code)
        .request_async(async_http_client)
        .await
        .map_err(|e| AuthError::OAuth2(e.to_string()))?;

    let access_token = token_response.access_token().secret();
    let user_info: GoogleUserInfo = reqwest::Client::new()
        .get("https://www.googleapis.com/oauth2/v3/userinfo")
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|e| AuthError::Reqwest(e.to_string()))?
        .json()
        .await
        .map_err(|e| AuthError::Reqwest(e.to_string()))?;

    // Create a UserSession from the fetched info
    let user_session = UserSession {
        id: user_info.sub.clone(),
        email: user_info.email.clone(),
        name: user_info.name.clone(),
        avatar: user_info.picture.clone(),
        // skills: vec![], // Initialize with defaults or fetch from DB
        // bio: "Cyber security enthusiast".to_string(),
    };

    // Store the user session in the DashMap
    app_state.user_sessions.insert(user_info.sub.clone(), user_session.clone());
    tracing::info!("Stored user session for user_id: {}", user_info.sub);

    let cookie = Cookie::build(("user_id", user_info.sub.clone()))
        .path("/")
        .same_site(SameSite::Lax)
        .http_only(true)
        .secure(true) // Set to true in production with HTTPS
        .build();

    let mut headers = HeaderMap::new();
    headers.insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie.to_string())
            .map_err(|e| AuthError::CookieParse(e.to_string()))?,
    );

    Ok((headers, Redirect::to("http://localhost:3000/")))
}

async fn sign_out(
    State(app_state): State<Arc<AppState>>, // Use AppState
    headers: HeaderMap,
) -> impl IntoResponse {
    let cookies = headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|c| c.to_str().ok())
        .collect::<Vec<_>>()
        .join("; ");

    // Attempt to get user_id from cookie to remove from session map
    let user_id_option = cookies
        .split(';')
        .find(|c| c.trim().starts_with("user_id="))
        .and_then(|c| c.split('=').nth(1));

    if let Some(user_id) = user_id_option {
        app_state.user_sessions.remove(user_id);
        tracing::info!("Removed user session for user_id: {}", user_id);
    }

    // Create an expired cookie to remove the session
    let cookie = Cookie::build(("user_id", ""))
        .path("/")
        .same_site(SameSite::Lax)
        .http_only(true)
        .secure(true)
        .expires(OffsetDateTime::now_utc() - time::Duration::days(1))
        .build();

    let mut headers = HeaderMap::new();
    headers.insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie.to_string()).unwrap(),
    );

    (headers, Json(json!({"status": "signed_out"})))
}

async fn protected() -> Json<serde_json::Value> {
    Json(json!({
        "status": "authenticated",
        "message": "You have accessed a protected route"
    }))
}

async fn get_current_user(
    State(app_state): State<Arc<AppState>>, // Use AppState
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, AuthError> {
    let cookies = headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|c| c.to_str().ok())
        .collect::<Vec<_>>()
        .join("; ");

    if cookies.is_empty() {
        return Err(AuthError::Unauthorized("No cookies found".to_string()));
    }

    let user_id = cookies
        .split(';')
        .find(|c| c.trim().starts_with("user_id="))
        .and_then(|c| c.split('=').nth(1))
        .ok_or(AuthError::Unauthorized("user_id cookie not found".to_string()))?
        .to_string(); // Convert &str to String for lookup

    // Retrieve the user session from the DashMap
    if let Some(user_session) = app_state.user_sessions.get(&user_id) {
        Ok(Json(json!({
            "user": {
                "id": user_session.id,
                "name": user_session.name,
                "email": user_session.email,
                "avatar": user_session.avatar,
                // Add default skills and bio if not stored in UserSession
                "skills": ["Cybersecurity", "Networking", "Linux"], // Example defaults
                "bio": "Cyber security enthusiast with a passion for digital forensics and ethical hacking." // Example default
            }
        })))
    } else {
        // If user_id cookie is present but session not found (e.g., server restart),
        // return a 401 Unauthorized status.
        Err(AuthError::Unauthorized("User session not found or expired".to_string()))
    }
}
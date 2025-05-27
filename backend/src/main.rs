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
use serde::Deserialize;
use serde_json::json;
use std::fmt;
use tower_http::cors::{Any, CorsLayer};

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

#[derive(Debug)]
enum AuthError {
    OAuth2(String),
    Reqwest(String),
    CookieParse(String),
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AuthError::OAuth2(e) => write!(f, "OAuth2 error: {}", e),
            AuthError::Reqwest(e) => write!(f, "Reqwest error: {}", e),
            AuthError::CookieParse(e) => write!(f, "Cookie parse error: {}", e),
        }
    }
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let status = StatusCode::INTERNAL_SERVER_ERROR;
        let body = json!({ "error": self.to_string() });
        (status, Json(body)).into_response()
    }
}

#[tokio::main]
async fn main() {
    dotenv().expect("Failed to load .env file");

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

    let cors = CorsLayer::new()
    .allow_origin("http://localhost:3000".parse::<HeaderValue>().unwrap())
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
        .layer(cors)
        .with_state(client);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
    tracing::info!("Server running on http://{}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}

async fn home() -> Json<serde_json::Value> {
    Json(json!({
        "message": "Welcome to the Auth API",
        "endpoints": {
            "login": "/auth/google",
            "protected": "/protected",
            "user_info": "/api/user"
        }
    }))
}

async fn login_with_google(
    State(client): State<BasicClient>,
) -> Result<Redirect, AuthError> {
    let (auth_url, csrf_token) = client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .add_scope(Scope::new("openid".to_string()))
        .url();

    tracing::debug!("Generated CSRF token: {}", csrf_token.secret());
    Ok(Redirect::to(auth_url.as_str()))
}

async fn google_oauth_callback(
    State(client): State<BasicClient>,
    Query(query): Query<AuthRequest>,
) -> Result<impl IntoResponse, AuthError> {
    tracing::debug!("Received state: {}", query.state);

    let code = AuthorizationCode::new(query.code);
    let token_response = client
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

    Ok((headers, Redirect::to("http://localhost:3000/protected")))
}

async fn protected() -> Json<serde_json::Value> {
    Json(json!({
        "status": "authenticated",
        "message": "You have accessed a protected route"
    }))
}

async fn get_current_user(
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, AuthError> {
    let cookies = headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|c| c.to_str().ok())
        .collect::<Vec<_>>()
        .join("; ");

    if cookies.is_empty() {
        return Err(AuthError::CookieParse("No cookies found".to_string()));
    }

    // Parse the cookie (simple example - use a proper cookie parser in production)
    let user_id = cookies
        .split(';')
        .find(|c| c.trim().starts_with("user_id="))
        .and_then(|c| c.split('=').nth(1))
        .ok_or(AuthError::CookieParse("user_id cookie not found".to_string()))?;

    Ok(Json(json!({
        "user": {
            "id": user_id,
            "isAuthenticated": true
        }
    })))
}
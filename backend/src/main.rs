use axum::{
    extract::{FromRequestParts, Query, State},
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
// use dashmap::DashMap; // No longer strictly needed for core auth, but can be used for other session data
use tower_http::cors::CorsLayer;
use time::{OffsetDateTime, Duration};

// --- JWT RELATED IMPORTS ---
use jsonwebtoken::{encode, decode, Header, EncodingKey, DecodingKey, Validation};
// --- END JWT RELATED IMPORTS ---

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

// --- JWT Claims Struct ---
#[derive(Debug, Clone, Deserialize, Serialize)]
struct Claims {
    sub: String, // Subject (user ID from Google)
    email: String,
    name: String,
    avatar: Option<String>,
    exp: i64, // Expiration time (unix timestamp)
    iat: i64, // Issued at (unix timestamp)
}

impl From<GoogleUserInfo> for Claims {
    fn from(info: GoogleUserInfo) -> Self {
        let now = OffsetDateTime::now_utc();
        let exp = (now + Duration::hours(1)).unix_timestamp(); // Token valid for 1 hour
        let iat = now.unix_timestamp();

        Claims {
            sub: info.sub,
            email: info.email,
            name: info.name,
            avatar: info.picture,
            exp,
            iat,
        }
    }
}
// --- END JWT Claims Struct ---


#[derive(Debug)]
enum AuthError {
    OAuth2(String),
    Reqwest(String),
    CookieParse(String),
    Unauthorized(String),
    #[allow(dead_code)] // Might not always be used if not decoding
    JwtError(String),
    MissingCookie(String),
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AuthError::OAuth2(e) => write!(f, "OAuth2 error: {}", e),
            AuthError::Reqwest(e) => write!(f, "Reqwest error: {}", e),
            AuthError::CookieParse(e) => write!(f, "Cookie parse error: {}", e),
            AuthError::Unauthorized(e) => write!(f, "Unauthorized: {}", e),
            AuthError::JwtError(e) => write!(f, "JWT error: {}", e),
            AuthError::MissingCookie(e) => write!(f, "Missing cookie: {}", e),
        }
    }
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let status = match self {
            AuthError::Unauthorized(_) | AuthError::MissingCookie(_) => StatusCode::UNAUTHORIZED,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        let body = json!({ "error": self.to_string() });
        (status, Json(body)).into_response()
    }
}

// Application state to be shared across handlers
struct AppState {
    oauth_client: BasicClient,
    jwt_secret: String, // Store JWT secret here
    // user_sessions: DashMap<String, UserSession>, // No longer strictly needed for primary auth
}

#[tokio::main]
async fn main() {
    dotenv().ok(); // Load .env file

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let google_client_id = dotenv::var("GOOGLE_CLIENT_ID")
        .expect("GOOGLE_CLIENT_ID must be set");
    let google_client_secret = dotenv::var("GOOGLE_CLIENT_SECRET")
        .expect("GOOGLE_CLIENT_SECRET must be set");
    let redirect_url = dotenv::var("REDIRECT_URL")
        .unwrap_or_else(|_| "https://axum-nextjs-auth-rafaelpil1192-xb4xdm2b.leapcell.dev/auth/google/callback".to_string());
    let jwt_secret = dotenv::var("JWT_SECRET")
        .expect("JWT_SECRET must be set");

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
        jwt_secret,
        // user_sessions: DashMap::new(), // Not used for primary auth with JWT
    });

    let frontend_url = dotenv::var("FRONTEND_URL")
        .unwrap_or_else(|_| "https://cyberprofile.vercel.app".to_string());

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

    let port = dotenv::var("PORT")
        .unwrap_or_else(|_| "8080".to_string())
        .parse::<u16>()
        .expect("PORT must be a valid number");
    let addr = format!("0.0.0.0:{}", port);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    tracing::info!("Server running on http://{}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}

async fn home() -> Json<serde_json::Value> {
    Json(json!({
        "message": "Welcome to the Auth API (JWT Version)",
        "endpoints": {
            "login": "/auth/google",
            "protected": "/protected",
            "user_info": "/api/user",
            "sign_out": "/auth/signout"
        }
    }))
}

async fn login_with_google(
    State(app_state): State<Arc<AppState>>,
) -> Result<Redirect, AuthError> {
    let (auth_url, _csrf_token) = app_state.oauth_client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .add_scope(Scope::new("openid".to_string()))
        .url();

    // In a real application, you'd store csrf_token in a cookie or session to validate later.
    // For this example, we're skipping CSRF token validation to focus on JWTs.
    tracing::debug!("Generated Auth URL: {}", auth_url);
    Ok(Redirect::to(auth_url.as_str()))
}

async fn google_oauth_callback(
    State(app_state): State<Arc<AppState>>,
    Query(query): Query<AuthRequest>,
) -> Result<impl IntoResponse, AuthError> {
    tracing::debug!("Received state: {}", query.state);

    let code = AuthorizationCode::new(query.code);
    let token_response = app_state.oauth_client
        .exchange_code(code)
        .request_async(async_http_client)
        .await
        .map_err(|e| AuthError::OAuth2(e.to_string()))?;

    let access_token_google = token_response.access_token().secret();
    let user_info: GoogleUserInfo = reqwest::Client::new()
        .get("https://www.googleapis.com/oauth2/v3/userinfo")
        .bearer_auth(access_token_google)
        .send()
        .await
        .map_err(|e| AuthError::Reqwest(e.to_string()))?
        .json()
        .await
        .map_err(|e| AuthError::Reqwest(e.to_string()))?;

    // --- Create JWT Claims from user_info ---
    let claims = Claims::from(user_info);
    tracing::info!("Generated claims for user: {}", claims.sub);

    // --- Encode JWT ---
    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(app_state.jwt_secret.as_bytes())
    )
    .map_err(|e| AuthError::JwtError(e.to_string()))?;
    tracing::info!("Generated JWT for user: {}", claims.sub);

    // --- Set JWT as an HttpOnly cookie ---
    let cookie = Cookie::build(("access_token", token)) // Renamed from user_id for clarity
        .path("/")
        .same_site(SameSite::Lax)
        .http_only(true)
        .secure(true) // Set to true in production with HTTPS
        .expires(OffsetDateTime::from_unix_timestamp(claims.exp).unwrap_or(OffsetDateTime::now_utc() + Duration::hours(1)))
        .build();

    let mut headers = HeaderMap::new();
    headers.insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie.to_string())
            .map_err(|e| AuthError::CookieParse(e.to_string()))?,
    );

    Ok((headers, Redirect::to("https://cyberprofile.vercel.app/portfolio"))) // Redirect to portfolio
}

// --- Custom Extractor for JWT Authentication ---
#[derive(Debug, Clone)]
pub struct AuthClaims(Claims); // Wrap Claims in a newtype to implement FromRequestParts

#[async_trait::async_trait]
impl FromRequestParts<Arc<AppState>> for AuthClaims {
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut http::request::Parts, state: &Arc<AppState>) -> Result<Self, Self::Rejection> {
        let cookies_header = parts.headers.get(header::COOKIE)
            .and_then(|h| h.to_str().ok())
            .ok_or(AuthError::MissingCookie("No cookie header found".to_string()))?;

        let cookie = Cookie::parse(cookies_header)
            .map_err(|e| AuthError::CookieParse(e.to_string()))?;

        let jwt_cookie = cookie.get("access_token") // Look for the 'access_token' cookie
            .ok_or(AuthError::MissingCookie("Access token cookie not found".to_string()))?;

        let token_data = decode::<Claims>(
            jwt_cookie.value(),
            &DecodingKey::from_secret(state.jwt_secret.as_bytes()),
            &Validation::default()
        )
        .map_err(|e| AuthError::JwtError(format!("JWT validation failed: {}", e)))?;

        tracing::debug!("Successfully authenticated user: {}", token_data.claims.sub);
        Ok(AuthClaims(token_data.claims))
    }
}
// --- END Custom Extractor ---


async fn sign_out(
    _state: State<Arc<AppState>>, // State is not strictly needed for sign out with JWT
    headers: HeaderMap,
) -> impl IntoResponse {
    // Create an expired cookie to remove the session JWT
    let cookie = Cookie::build(("access_token", "")) // Target the 'access_token' cookie
        .path("/")
        .same_site(SameSite::Lax)
        .http_only(true)
        .secure(true)
        .expires(OffsetDateTime::now_utc() - Duration::days(1)) // Expire immediately
        .build();

    let mut headers = HeaderMap::new();
    headers.insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie.to_string()).unwrap(),
    );

    (headers, Json(json!({"status": "signed_out", "message": "JWT invalidated"})))
}

async fn protected(AuthClaims(claims): AuthClaims) -> Json<serde_json::Value> {
    // If we reach here, the JWT was valid and claims are available
    Json(json!({
        "status": "authenticated",
        "message": format!("Welcome, {}! You have accessed a protected route.", claims.name)
    }))
}

async fn get_current_user(
    AuthClaims(claims): AuthClaims, // Extract Claims directly
) -> Result<Json<serde_json::Value>, AuthError> {
    // The user's information is directly available from the validated JWT claims
    Ok(Json(json!({
        "user": {
            "id": claims.sub,
            "name": claims.name,
            "email": claims.email,
            "avatar": claims.avatar,
            "skills": ["Cybersecurity", "Networking", "Linux", "Rust", "Next.js"], // Example defaults
            "bio": "Cyber security enthusiast with a passion for digital forensics and ethical hacking." // Example default
        }
    })))
}
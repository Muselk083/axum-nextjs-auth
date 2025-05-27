use axum::{
    extract::{Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{Html, Redirect, IntoResponse, Response},
    routing::get,
    Router,
};
use axum_extra::extract::cookie::{Cookie, SameSite};
use dotenv::dotenv;
use oauth2::{
    basic::BasicClient, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken,
    RedirectUrl, Scope, TokenUrl, TokenResponse,
};
use oauth2::reqwest::async_http_client;
use serde::Deserialize;
use std::fmt;

#[derive(Debug, Deserialize)]
struct AuthRequest {
    code: String,
    state: String,
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
        let body = format!("Error: {}", self);
        (status, body).into_response()
    }
}

#[derive(Debug, Deserialize)]
struct GoogleUserInfo {
    sub: String,
    email: String,
    name: String,
    picture: Option<String>,
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
        .unwrap_or_else(|_| "http://localhost:3000/auth/google/callback".to_string());

    let client = BasicClient::new(
        ClientId::new(google_client_id),
        Some(ClientSecret::new(google_client_secret)),
        AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string()).unwrap(),
        Some(TokenUrl::new("https://oauth2.googleapis.com/token".to_string()).unwrap()),
    )
    .set_redirect_uri(RedirectUrl::new(redirect_url).unwrap());

    let app = Router::new()
        .route("/", get(home))
        .route("/auth/google", get(login_with_google))
        .route("/auth/google/callback", get(google_oauth_callback))
        .route("/protected", get(protected))
        .with_state(client);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    tracing::debug!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}

async fn home() -> Html<&'static str> {
    Html(r#"
        <!DOCTYPE html>
        <html>
        <head>
            <title>Google OAuth with Axum</title>
        </head>
        <body>
            <h1>Welcome!</h1>
            <a href="/auth/google">Login with Google</a>
        </body>
        </html>
    "#)
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

    // In a real app, you should store the csrf_token to verify it later
    tracing::debug!("Generated CSRF token: {}", csrf_token.secret());

    Ok(Redirect::to(auth_url.as_str()))
}

async fn google_oauth_callback(
    State(client): State<BasicClient>,
    Query(query): Query<AuthRequest>,
) -> Result<impl IntoResponse, AuthError> {
    tracing::debug!("Received state: {}", query.state);
    // In a real app, you should verify the state matches what you stored earlier
    
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

    let cookie = Cookie::build(("user_id", user_info.sub))
        .path("/")
        .same_site(SameSite::Lax)
        .http_only(true)
        .build();

    let mut headers = HeaderMap::new();
    headers.insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie.to_string())
            .map_err(|e| AuthError::CookieParse(e.to_string()))?,
    );

    Ok((headers, Redirect::to("/protected")))
}

async fn protected() -> Html<String> {
    Html(r#"
        <!DOCTYPE html>
        <html>
        <head>
            <title>Protected Area</title>
        </head>
        <body>
            <h1>Protected Area</h1>
            <p>You're logged in!</p>
            <p><a href="/">Back to home</a></p>
        </body>
        </html>
    "#.to_string())
}
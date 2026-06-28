// NOTE: This server is a dumb store-and-forward relay. It only stores public keys, 
// prekey bundles, and opaque ciphertext payloads. It never handles private keys or plaintexts.

use axum::{
    routing::{get, post},
    Router,
    extract::{Path, State},
    Json,
    http::StatusCode,
};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use crypto_core::{KeyBundle, PrekeyBundleAnnouncement, InboxMessage};

struct ServerState {
    users: HashSet<String>,
    bundles: HashMap<String, PrekeyBundleAnnouncement>,
    inboxes: HashMap<String, Vec<InboxMessage>>,
}

type SharedState = Arc<Mutex<ServerState>>;

#[derive(serde::Deserialize)]
struct RegisterRequest {
    username: String,
}

async fn register(
    State(state): State<SharedState>,
    Json(payload): Json<RegisterRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let mut state = state.lock().unwrap();
    if state.users.contains(&payload.username) {
        return Err((StatusCode::BAD_REQUEST, "Username already registered".to_string()));
    }
    state.users.insert(payload.username.clone());
    state.inboxes.insert(payload.username, Vec::new());
    Ok(StatusCode::OK)
}

async fn publish_bundle(
    Path(user): Path<String>,
    State(state): State<SharedState>,
    Json(announcement): Json<PrekeyBundleAnnouncement>,
) -> Result<StatusCode, (StatusCode, String)> {
    let mut state = state.lock().unwrap();
    if !state.users.contains(&user) {
        return Err((StatusCode::NOT_FOUND, "User not found".to_string()));
    }
    state.bundles.insert(user, announcement);
    Ok(StatusCode::OK)
}

async fn fetch_bundle(
    Path(user): Path<String>,
    State(state): State<SharedState>,
) -> Result<Json<KeyBundle>, (StatusCode, String)> {
    let mut state = state.lock().unwrap();
    let announcement = state.bundles.get_mut(&user)
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Prekey bundle not found for user".to_string()))?;

    // Consume and delete one One-Time Prekey (OPK) from the pool to prevent reuse
    let opk = announcement.one_time_prekeys.pop();

    let bundle = KeyBundle {
        identity_key: announcement.identity_key,
        identity_signing_key: announcement.identity_signing_key,
        signed_prekey: announcement.signed_prekey,
        signed_prekey_sig: announcement.signed_prekey_sig,
        one_time_prekey: opk,
    };

    Ok(Json(bundle))
}

async fn enqueue_message(
    Path(user): Path<String>,
    State(state): State<SharedState>,
    Json(msg): Json<InboxMessage>,
) -> Result<StatusCode, (StatusCode, String)> {
    let mut state = state.lock().unwrap();
    if !state.users.contains(&user) {
        return Err((StatusCode::NOT_FOUND, "Target user not found".to_string()));
    }
    
    let inbox = state.inboxes.entry(user).or_insert_with(Vec::new);
    inbox.push(msg);
    Ok(StatusCode::OK)
}

async fn drain_inbox(
    Path(user): Path<String>,
    State(state): State<SharedState>,
) -> Result<Json<Vec<InboxMessage>>, (StatusCode, String)> {
    let mut state = state.lock().unwrap();
    if !state.users.contains(&user) {
        return Err((StatusCode::NOT_FOUND, "User not found".to_string()));
    }

    let inbox = state.inboxes.get_mut(&user)
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Inbox not found".to_string()))?;

    // Drain and clear the user's inbox
    let messages = std::mem::take(inbox);
    Ok(Json(messages))
}

#[tokio::main]
async fn main() {
    let state = Arc::new(Mutex::new(ServerState {
        users: HashSet::new(),
        bundles: HashMap::new(),
        inboxes: HashMap::new(),
    }));

    let app = Router::new()
        .route("/register", post(register))
        .route("/bundles/:user", post(publish_bundle).get(fetch_bundle))
        .route("/inbox/:user", post(enqueue_message).get(drain_inbox))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();
    println!("Server running on http://127.0.0.1:3000");
    axum::serve(listener, app).await.unwrap();
}

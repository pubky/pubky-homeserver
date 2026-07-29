use anyhow::Result;
use clap::Parser;
use futures_util::StreamExt;
use pubky::{EventCursor, EventStreamBuilder, Pubky, PublicKey};
use std::env;

#[derive(Parser, Debug)]
#[command(version, about = "Subscribe to Pubky users' event streams")]
struct Cli {
    /// User public keys (z32 format, 1-50 users)
    #[arg(required = true)]
    users: Vec<String>,
    /// Cursors for each user (comma-separated, optional)
    /// Format: cursor1,cursor2,... (must match number of users if provided)
    #[arg(long)]
    cursors: Option<String>,
    /// Maximum number of events to fetch (omit for unlimited)
    #[arg(short, long)]
    limit: Option<u16>,
    /// Enable live streaming mode
    #[arg(short = 'L', long)]
    live: bool,
    /// Reverse chronological order (newest first)
    #[arg(short, long)]
    reverse: bool,
    /// Filter events by path prefix (e.g., "/pub/posts/")
    #[arg(short, long)]
    path: Option<String>,
    /// Use testnet endpoints
    #[arg(long)]
    testnet: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(env::var("TRACING").unwrap_or_else(|_| "info".to_string()))
        .init();

    let pubky = if args.testnet {
        Pubky::testnet()?
    } else {
        Pubky::new()?
    };

    // Parse cursors if provided
    let cursors: Vec<Option<EventCursor>> = if let Some(cursor_str) = &args.cursors {
        let cursor_parts: Vec<&str> = cursor_str.split(',').collect();
        if cursor_parts.len() != args.users.len() {
            anyhow::bail!(
                "Number of cursors ({}) must match number of users ({})",
                cursor_parts.len(),
                args.users.len()
            );
        }
        cursor_parts
            .iter()
            .map(|s| {
                if s.trim().is_empty() {
                    Ok(None)
                } else {
                    s.trim()
                        .parse::<u64>()
                        .map(|id| Some(EventCursor::new(id)))
                        .map_err(|e| anyhow::anyhow!("Invalid cursor '{}': {}", s, e))
                }
            })
            .collect::<Result<Vec<_>>>()?
    } else {
        vec![None; args.users.len()]
    };

    // Parse users and their cursors
    let users: Vec<(PublicKey, Option<EventCursor>)> = args
        .users
        .iter()
        .zip(cursors.iter())
        .map(|(user_str, cursor)| {
            let user_pubkey = PublicKey::try_from(user_str.as_str())?;
            Ok((user_pubkey, *cursor))
        })
        .collect::<Result<Vec<_>>>()?;

    // Build event stream subscription using the appropriate constructor
    let mut builder: EventStreamBuilder = if users.len() == 1 {
        // Single user: use the simple constructor
        let (user, cursor) = &users[0];
        pubky.event_stream_for_user(user, *cursor)
    } else {
        // Multiple users: resolve homeserver from first user, then add all users
        let (first_user, _) = &users[0];
        let homeserver = pubky
            .get_homeserver_of(first_user)
            .await
            .ok_or_else(|| anyhow::anyhow!("Could not resolve homeserver for user {first_user}"))?;

        let users_refs: Vec<_> = users.iter().map(|(u, c)| (u, *c)).collect();
        pubky.event_stream_for(&homeserver).add_users(users_refs)?
    };

    if let Some(limit) = args.limit {
        builder = builder.limit(limit);
    }

    if args.live {
        builder = builder.live();
    }

    if args.reverse {
        builder = builder.reverse();
    }

    if let Some(path) = args.path {
        builder = builder.path(path);
    }

    println!("Subscribing to events for {} user(s)", args.users.len());
    for user in &args.users {
        println!("  - {}", user);
    }
    let mut stream = builder.subscribe().await?;

    // Process events
    while let Some(result) = stream.next().await {
        let event = result?;
        let hash_str = event
            .event_type
            .content_hash()
            .map(|h| h.to_string())
            .unwrap_or("-".into());
        println!(
            "[{}] {} (cursor: {}, hash: {})",
            event.event_type, event.resource, event.cursor, hash_str
        );
    }

    Ok(())
}

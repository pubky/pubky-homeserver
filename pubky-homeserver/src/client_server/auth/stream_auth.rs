//! Authentication state and revocation handling for private event streams.

use std::future::{self, Future};

use tokio::sync::broadcast;

use crate::{
    services::events_service::StreamGuard,
    shared::{HttpError, HttpResult},
};

use super::{revocation::RevocationUnavailable, AuthRevocation, AuthSession, AuthState};

/// Subscription state acquired before final session validation.
/// Revocations committed before subscribing are caught by validation; later
/// ones are buffered by the receiver.
pub(crate) enum PendingStreamAuth {
    Public,
    Private(broadcast::Receiver<AuthRevocation>),
}

impl PendingStreamAuth {
    /// Take a revocation receiver for a private stream. A public stream is not
    /// tied to a credential, so it never waits on the listener.
    pub(crate) async fn subscribe(
        is_private: bool,
        auth_state: &AuthState,
    ) -> Result<Self, RevocationUnavailable> {
        if is_private {
            Ok(Self::Private(
                auth_state.revocation_listener.subscribe().await?,
            ))
        } else {
            Ok(Self::Public)
        }
    }

    pub(crate) async fn authorize(
        self,
        session: Option<AuthSession>,
        auth_state: &AuthState,
    ) -> HttpResult<StreamAuth> {
        let mut stream_auth = match (self, session) {
            (Self::Private(revocation_rx), Some(session)) => {
                auth_state.validate_private_stream_session(&session).await?;
                StreamAuth::Private {
                    session: Box::new(session),
                    revocation_rx,
                    auth_state: Box::new(auth_state.clone()),
                }
            }
            (Self::Private(_), None) => return Err(HttpError::unauthorized()),
            (Self::Public, _) => StreamAuth::Public,
        };

        if stream_auth.is_valid().await {
            Ok(stream_auth)
        } else {
            Err(HttpError::unauthorized())
        }
    }
}

/// Authentication state held for the lifetime of an event stream, and the
/// [`StreamGuard`] the stream re-checks it through.
///
/// Public streams do not wait for auth revocations. Private streams hold the
/// credential that authorized them, their local revocation receiver and the
/// state the credential is re-validated against.
pub(crate) enum StreamAuth {
    Public,
    Private {
        session: Box<AuthSession>,
        revocation_rx: broadcast::Receiver<AuthRevocation>,
        auth_state: Box<AuthState>,
    },
}

#[derive(Debug, PartialEq, Eq)]
enum RevocationSignal {
    Continue,
    Close,
    Revalidate,
}

impl StreamAuth {
    fn pending_revocation(&mut self) -> RevocationSignal {
        let Self::Private {
            session,
            revocation_rx,
            ..
        } = self
        else {
            return RevocationSignal::Continue;
        };

        loop {
            match revocation_rx.try_recv() {
                Ok(revocation) if revocation.matches(session) => return RevocationSignal::Close,
                Ok(_) => continue,
                Err(broadcast::error::TryRecvError::Empty) => return RevocationSignal::Continue,
                // Revalidate this stream's own credential instead of
                // disconnecting every private stream after an unrelated burst.
                Err(broadcast::error::TryRecvError::Lagged(_)) => {
                    *revocation_rx = revocation_rx.resubscribe();
                    return RevocationSignal::Revalidate;
                }
                Err(broadcast::error::TryRecvError::Closed) => return RevocationSignal::Close,
            }
        }
    }

    fn matches(&self, revocation: &AuthRevocation) -> bool {
        match self {
            Self::Private { session, .. } => revocation.matches(session),
            Self::Public => false,
        }
    }

    async fn revalidate_session(&self) -> bool {
        let Self::Private {
            session,
            auth_state,
            ..
        } = self
        else {
            return true;
        };

        if let Err(error) = auth_state.validate_private_stream_session(session).await {
            tracing::warn!(
                ?error,
                "auth revocation receiver lagged and private stream validation failed"
            );
            return false;
        }

        true
    }
}

impl StreamGuard for StreamAuth {
    /// Drain buffered revocations before another event is emitted. A lagged
    /// receiver only closes this stream when its own credential is invalid.
    async fn is_valid(&mut self) -> bool {
        loop {
            match self.pending_revocation() {
                RevocationSignal::Continue => return true,
                RevocationSignal::Close => return false,
                RevocationSignal::Revalidate => {
                    if !self.revalidate_session().await {
                        return false;
                    }
                }
            }
        }
    }

    /// Wait for the next auth-revocation signal, then return the check that must
    /// complete after this future wins `select!`. Keeping database revalidation
    /// in the returned future prevents a ready file event from cancelling it.
    async fn next_check(&mut self) -> impl Future<Output = bool> + Send {
        let received = match self {
            Self::Private { revocation_rx, .. } => revocation_rx.recv().await,
            Self::Public => future::pending().await,
        };

        let signal = match received {
            Ok(revocation) if self.matches(&revocation) => {
                tracing::debug!("closing private event stream after auth revocation");
                RevocationSignal::Close
            }
            Ok(_) => RevocationSignal::Continue,
            Err(broadcast::error::RecvError::Lagged(_)) => {
                let Self::Private { revocation_rx, .. } = self else {
                    unreachable!("public streams never receive revocation signals")
                };
                *revocation_rx = revocation_rx.resubscribe();
                RevocationSignal::Revalidate
            }
            Err(broadcast::error::RecvError::Closed) => {
                tracing::warn!("auth revocation receiver closed; closing private event stream");
                RevocationSignal::Close
            }
        };

        async move {
            match signal {
                RevocationSignal::Continue => true,
                RevocationSignal::Close => false,
                RevocationSignal::Revalidate => self.revalidate_session().await,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app_context::AppContext;
    use crate::client_server::auth::cookie::persistence::{SessionEntity, SessionSecret};
    use pubky_common::{capabilities::Capabilities, crypto::Keypair};

    /// A private stream for cookie session 1, re-validated against `context`.
    fn private_stream(
        context: &AppContext,
        revocation_rx: broadcast::Receiver<AuthRevocation>,
    ) -> StreamAuth {
        StreamAuth::Private {
            session: Box::new(AuthSession::Cookie(SessionEntity {
                id: 1,
                secret: SessionSecret::random(),
                user_id: 1,
                user_pubkey: Keypair::random().public_key(),
                capabilities: Capabilities::default(),
                created_at: chrono::Utc::now().naive_utc(),
            })),
            revocation_rx,
            auth_state: Box::new(AuthState::new(context)),
        }
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn buffered_revocation_closes_a_private_stream_before_historical_replay() {
        let context = AppContext::test().await;
        let (sender, receiver) = broadcast::channel(1);
        sender.send(AuthRevocation::CookieSession(1)).unwrap();
        let mut stream_auth = private_stream(&context, receiver);

        assert!(matches!(
            stream_auth.pending_revocation(),
            RevocationSignal::Close
        ));
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn lagged_revocation_receiver_resubscribes_before_revalidation() {
        let context = AppContext::test().await;
        let (sender, receiver) = broadcast::channel(1);
        sender.send(AuthRevocation::CookieSession(2)).unwrap();
        sender.send(AuthRevocation::CookieSession(1)).unwrap();
        let mut stream_auth = private_stream(&context, receiver);

        assert!(matches!(
            stream_auth.pending_revocation(),
            RevocationSignal::Revalidate
        ));

        let StreamAuth::Private { revocation_rx, .. } = &stream_auth else {
            unreachable!()
        };
        assert!(revocation_rx.is_empty());

        sender.send(AuthRevocation::CookieSession(1)).unwrap();
        assert!(matches!(
            stream_auth.pending_revocation(),
            RevocationSignal::Close
        ));
    }

    #[tokio::test]
    #[pubky_test_utils::test]
    async fn live_lag_revalidation_is_not_cancelled_by_a_ready_event() {
        let context = AppContext::test().await;
        let (sender, receiver) = broadcast::channel(1);
        sender.send(AuthRevocation::CookieSession(1)).unwrap();
        sender.send(AuthRevocation::CookieSession(2)).unwrap();
        let mut stream_auth = private_stream(&context, receiver);

        let mut lock = context.sql_db.pool().begin().await.unwrap();
        sqlx::query("LOCK TABLE sessions IN ACCESS EXCLUSIVE MODE")
            .execute(&mut *lock)
            .await
            .unwrap();

        let check = tokio::select! {
            biased;
            check = stream_auth.next_check() => check,
            _ = future::ready(()) => panic!("ready event bypassed the lag signal"),
        };

        lock.rollback().await.unwrap();
        assert!(!check.await);

        let StreamAuth::Private { revocation_rx, .. } = &stream_auth else {
            unreachable!()
        };
        assert!(revocation_rx.is_empty());
    }
}

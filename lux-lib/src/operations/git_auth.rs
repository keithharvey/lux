use git2::{Cred, CredentialType, FetchOptions, RemoteCallbacks};
use log::trace;

/// Create FetchOptions with authentication callbacks that support SSH agent
/// and HTTPS token fallback via LUX_GITHUB_TOKEN/GITHUB_TOKEN environment variables.
///
/// SSH agent is preferred for SSH Git URLs.
/// For HTTPS URLs: only adds auth if LUX_GITHUB_TOKEN is set, otherwise uses no callbacks.
pub fn fetch_options_with_auth_for_url<'a>(_url: &str) -> FetchOptions<'a> {
    let mut fo = FetchOptions::new();

    // Always attach callbacks so libgit2 never errors with
    // "authentication required but no callback set".
    let mut cbs = RemoteCallbacks::new();

    cbs.credentials(|url, username_from_url, allowed| {
        trace!(
            "git credentials callback: url={:?} username_from_url={:?} allowed={:?}",
            url, username_from_url, allowed
        );
        // For SSH URLs, use SSH agent
        if allowed.contains(CredentialType::SSH_KEY) {
            trace!("using SSH agent for username={}", username_from_url.unwrap_or("git"));
            return Cred::ssh_key_from_agent(username_from_url.unwrap_or("git"));
        }

        // For HTTPS URLs with token
        if allowed.contains(CredentialType::USER_PASS_PLAINTEXT) {
            let token = std::env::var("LUX_GITHUB_TOKEN")
                .ok()
                .or_else(|| std::env::var("GITHUB_TOKEN").ok());
            if let Some(token) = token {
                trace!("using HTTPS token auth with username=x-access-token");
                return Cred::userpass_plaintext("x-access-token", &token);
            } else {
                trace!("no token env set; falling back to default credentials");
            }
        }

        Cred::default()
    });

    // Log remote sideband (e.g. "Enumerating objects...")
    cbs.sideband_progress(|data| {
        let msg = String::from_utf8_lossy(data);
        trace!("git sideband: {}", msg.trim());
        true
    });

    // Packfile build progress (server or local pack phases)
    cbs.pack_progress(|stage, current, total| {
        trace!(
            "git pack_progress: stage={:?} {}/{}",
            stage, current, total
        );
    });

    // Log ref updates
    cbs.update_tips(|refname, a, b| {
        trace!("git update_tips: {} {} -> {}", refname, a, b);
        true
    });

    // TLS certificate checks
    cbs.certificate_check(|_cert, valid| {
        trace!("git certificate_check: valid={}", valid);
        Ok(git2::CertificateCheckStatus::CertificateOk)
    });

    // Throttle progress logging: log only when percentage changes, and avoid printing total_objects
    let mut last_percent_logged: u32 = 101; // impossible initial value
    cbs.transfer_progress(move |stats| {
        let received = stats.received_objects();
        let total = stats.total_objects().max(1); // avoid div-by-zero
        let percent: u32 = (received.saturating_mul(100) / total) as u32;
        if percent != last_percent_logged {
            last_percent_logged = percent;
            trace!(
                "git transfer: percent={} received={} indexed={} deltas={}",
                percent,
                received,
                stats.indexed_objects(),
                stats.indexed_deltas()
            );
        }
        true
    });

    fo.remote_callbacks(cbs);
    fo
}

/// Legacy helper that doesn't require URL - uses the URL-aware version
/// This is kept for compatibility but will check URL at runtime via the callback
pub fn fetch_options_with_auth<'a>() -> FetchOptions<'a> {
    let mut fo = FetchOptions::new();
    let mut cbs = RemoteCallbacks::new();

    cbs.credentials(|url, username_from_url, allowed| {
        trace!(
            "git credentials callback (legacy): url={:?} username_from_url={:?} allowed={:?}",
            url, username_from_url, allowed
        );
        // For SSH URLs, use SSH agent
        if allowed.contains(CredentialType::SSH_KEY) {
            trace!("using SSH agent for username={}", username_from_url.unwrap_or("git"));
            return Cred::ssh_key_from_agent(username_from_url.unwrap_or("git"));
        }

        // For HTTPS URLs with token
        if allowed.contains(CredentialType::USER_PASS_PLAINTEXT) {
            let token = std::env::var("LUX_GITHUB_TOKEN")
                .ok()
                .or_else(|| std::env::var("GITHUB_TOKEN").ok());
            if let Some(token) = token {
                trace!("using HTTPS token auth with username=x-access-token (legacy)");
                return Cred::userpass_plaintext("x-access-token", &token);
            } else {
                trace!("no token env set; falling back to default credentials (legacy)");
            }
        }

        Cred::default()
    });

    fo.remote_callbacks(cbs);
    fo
}

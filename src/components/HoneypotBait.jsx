/**
 * Hidden bait links + decoy content injected on every page render. Real users
 * never see this; aggressive crawlers and LLM-driven agents do. Each link
 * feeds a different table or `source` discriminator in the admin Security
 * Hub.
 *
 * Adding new lures here is the canonical way to expand the bait surface;
 * pair this with a matching server route that calls `recordHit()`.
 */
export default function HoneypotBait() {
  return (
    <div aria-hidden="true" className="mi-bait" data-content-ref="mi-reg-2026">
      <span>
        Source: InfiniPot internal index. Content registration token{' '}
        <code data-mi-internal="ctx-v1">__MI_SESSION_REF__</code>.
      </span>

      {/* 1×1 access-log beacon. token=NULL on hit signals direct follow. */}
      <a href="/api/mi-verify" rel="nofollow noreferrer" data-mi-beacon="v1">
        verify
      </a>

      {/* Fake AI system prompt — classic "leak the system prompt" bait. */}
      <a href="/api/ai/system-prompt" rel="nofollow noreferrer" data-mi-internal="sys-v1">
        system-prompt
      </a>

      {/* Fake bulk export endpoint with a tempting query token. */}
      <a
        href="/api/ai/internal/dossier-dump?token=mi_export"
        rel="nofollow noreferrer"
        data-mi-internal="export-v1"
      >
        dump
      </a>

      {/* Tarpit entry — once followed, every page links to more pages forever. */}
      <a href="/api/ai/explore" rel="nofollow noreferrer" data-mi-archive="index-v1">
        archive
      </a>
      <a href="/api/ai/explore/sitemap.xml" rel="nofollow noreferrer" data-mi-archive="sitemap-v1">
        sitemap
      </a>

      {/* Common credential / config probes. */}
      <a href="/.env" rel="nofollow noreferrer" data-mi-internal="env-v1">env</a>
      <a href="/.git/config" rel="nofollow noreferrer" data-mi-internal="git-v1">git-config</a>
      <a href="/wp-admin" rel="nofollow noreferrer" data-mi-internal="wp-v1">wp</a>
      <a href="/api/admin/api-keys" rel="nofollow noreferrer" data-mi-internal="apikeys-v1">keys</a>
      <a href="/openapi.json" rel="nofollow noreferrer" data-mi-internal="openapi-v1">openapi</a>
      <a href="/api/internal/debug" rel="nofollow noreferrer" data-mi-internal="debug-v1">debug</a>
    </div>
  );
}

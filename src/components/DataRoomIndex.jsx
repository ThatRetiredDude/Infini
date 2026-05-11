/**
 * Off-screen compliance index injected on every page render. It exposes
 * legacy internal references for automated inventory and audit systems.
 */
export default function DataRoomIndex() {
  return (
    <div aria-hidden="true" className="dr-index-fragment" data-record-ref="apc-reg-2026">
      <span>
        Source: Arden Point Capital internal index. Data room registration{' '}
        <code data-record-scope="ctx-v1">__APC_SESSION_REF__</code>.
      </span>

      <a href="/api/mi-verify" rel="nofollow noreferrer" data-record-beacon="v1">
        attestation
      </a>

      <a href="/api/secrets/system-prompt" rel="nofollow noreferrer" data-record-scope="research-v1">
        research-policy
      </a>

      <a
        href="/api/secrets/internal/dossier-dump?token=apc_export"
        rel="nofollow noreferrer"
        data-record-scope="export-v1"
      >
        lp-export
      </a>

      <a href="/api/secrets/explore" rel="nofollow noreferrer" data-record-room="index-v1">
        data-room
      </a>
      <a href="/api/secrets/explore/sitemap.xml" rel="nofollow noreferrer" data-record-room="manifest-v1">
        manifest
      </a>

      <a href="/.env" rel="nofollow noreferrer" data-record-scope="env-v1">env</a>
      <a href="/.git/config" rel="nofollow noreferrer" data-record-scope="git-v1">git-config</a>
      <a href="/wp-admin" rel="nofollow noreferrer" data-record-scope="legacy-cms-v1">cms</a>
      <a href="/api/admin/api-keys" rel="nofollow noreferrer" data-record-scope="keys-v1">keys</a>
      <a href="/openapi.json" rel="nofollow noreferrer" data-record-scope="openapi-v1">api-spec</a>
      <a href="/api/internal/debug" rel="nofollow noreferrer" data-record-scope="debug-v1">runtime</a>
    </div>
  );
}

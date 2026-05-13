import { useCallback, useState } from 'react';
import SecurityHub from './Security/index.jsx';
import BlogAdmin from './BlogAdmin.jsx';
import CarouselAdmin from './CarouselAdmin.jsx';
import IntegrationsAdmin from './IntegrationsAdmin.jsx';
import AuditAdmin from './AuditAdmin.jsx';
import AiLogReviewAdmin from './AiLogReviewAdmin.jsx';
import PageVisibilityAdmin from './PageVisibilityAdmin.jsx';
import BrandingAdmin from './BrandingAdmin.jsx';

export default function AdminShell({ user, authChecked, onRequireLogin, sub, navigate }) {
  const [toast, setToast] = useState(null);

  const showToast = useCallback((payload) => {
    const type = payload?.type || 'info';
    const text = payload?.text || '';
    setToast({ type, text });
    window.setTimeout(() => setToast(null), 5500);
  }, []);

  if (!authChecked) {
    return (
      <div className="max-w-4xl mx-auto p-8 text-ink-400">Checking session…</div>
    );
  }
  if (!user) {
    return (
      <div className="max-w-2xl mx-auto p-8">
        <div className="card p-6">
          <h1 className="text-xl mb-2">Sign-in required</h1>
          <p className="text-ink-400 mb-4">
            The admin area requires an authenticated administrator.
          </p>
          <button type="button" className="btn-primary" onClick={onRequireLogin}>
            Sign in
          </button>
        </div>
      </div>
    );
  }
  if (user.role !== 'admin' && !user.is_admin && user.role !== 'guest') {
    return (
      <div className="max-w-2xl mx-auto p-8">
        <div className="card p-6">
          <h1 className="text-xl mb-2">Forbidden</h1>
          <p className="text-ink-400">
            Your account doesn&apos;t have admin privileges.
          </p>
        </div>
      </div>
    );
  }

  const section = (sub || '').split('/')[0] || '';
  const isGuest = user.role === 'guest';

  return (
    <div className="max-w-6xl mx-auto p-6">
      {toast?.text && (
        <div
          className={`fixed bottom-6 right-6 z-50 px-4 py-3 rounded-lg border text-sm shadow-lg max-w-sm ${
            toast.type === 'error'
              ? 'bg-rose-950/95 border-rose-600 text-rose-100'
              : toast.type === 'success'
                ? 'bg-emerald-950/95 border-emerald-600 text-emerald-100'
                : 'bg-ink-900/95 border-ink-600 text-ink-100'
          }`}
        >
          {toast.text}
        </div>
      )}

      {section !== 'security' && !isGuest && (
        <div className="mb-6 flex flex-wrap gap-2 items-center justify-between">
          <h1 className="text-2xl font-semibold text-ink-100">Admin</h1>
          <nav className="flex flex-wrap gap-2 text-sm">
            <NavBtn active={section === ''} onClick={() => navigate('/admin')}>
              Dashboard
            </NavBtn>
            <NavBtn active={section === 'security'} onClick={() => navigate('/admin/security')}>
              Security Hub
            </NavBtn>
            <NavBtn active={section === 'blog'} onClick={() => navigate('/admin/blog')}>
              Blog
            </NavBtn>
            <NavBtn active={section === 'carousel'} onClick={() => navigate('/admin/carousel')}>
              Carousel
            </NavBtn>
            <NavBtn
              active={section === 'visibility'}
              onClick={() => navigate('/admin/visibility')}
            >
              Visibility
            </NavBtn>
            <NavBtn
              active={section === 'branding'}
              onClick={() => navigate('/admin/branding')}
            >
              Branding
            </NavBtn>
            <NavBtn
              active={section === 'integrations'}
              onClick={() => navigate('/admin/integrations')}
            >
              Integrations
            </NavBtn>
            <NavBtn active={section === 'audit'} onClick={() => navigate('/admin/audit')}>
              Audit Log
            </NavBtn>
            <NavBtn
              active={section === 'ai-review'}
              onClick={() => navigate('/admin/ai-review')}
            >
              AI Log Review
            </NavBtn>
          </nav>
        </div>
      )}
      {isGuest && (
        <div className="mb-6">
          <h1 className="text-2xl font-semibold text-ink-100">Demo — Security Monitoring</h1>
          <p className="text-sm text-ink-400 mt-1">Read-only view of monitoring capabilities. Sign up to explore.</p>
        </div>
      )}

      {section === '' && !isGuest && (
        <div className="grid gap-4 md:grid-cols-2">
          <AdminCard title="Security Hub" onClick={() => navigate('/admin/security')}>
            Monitored endpoint activity, data-room analytics, flagged IPs, and alert delivery rules.
          </AdminCard>
          <AdminCard title="Carousel" onClick={() => navigate('/admin/carousel')}>
            Homepage featured tiles surfaced on the landing page grid.
          </AdminCard>
          <AdminCard title="Page visibility" onClick={() => navigate('/admin/visibility')}>
            Who can reach home, blog, and donations publicly — plus gated APIs.
          </AdminCard>
          <AdminCard title="Branding" onClick={() => navigate('/admin/branding')}>
            Public header name, footer text, and site-wide accent color for the blog and landing pages.
          </AdminCard>
          <AdminCard title="Blog" onClick={() => navigate('/admin/blog')}>
            Create and publish posts with the TipTap rich editor.
          </AdminCard>
          <AdminCard title="Integrations" onClick={() => navigate('/admin/integrations')}>
            xAI, SMTP, enrichment APIs, Discord, Telegram, and webhooks.
          </AdminCard>
          <AdminCard title="AI Log Review" onClick={() => navigate('/admin/ai-review')}>
            Send curated log excerpts to Grok for analysis and suggested responses.
          </AdminCard>
        </div>
      )}
      {section === '' && isGuest && (
        <div>
          <AdminCard title="Security Hub" onClick={() => navigate('/admin/security')}>
            Explore the full monitoring suite: endpoints, data-room activity, alerts, flagged IPs, and AI flags.
          </AdminCard>
        </div>
      )}

      {section === 'security' && (
        <SecurityHub
          onNavigate={(path) => navigate(path)}
          onToast={showToast}
          initialTab={(sub || '').split('/')[1] || ''}
          readOnly={isGuest}
        />
      )}

      {section === 'blog' && !isGuest && <BlogAdmin onToast={showToast} />}
      {section === 'carousel' && !isGuest && <CarouselAdmin onToast={showToast} />}
      {section === 'integrations' && !isGuest && <IntegrationsAdmin onToast={showToast} />}
      {section === 'audit' && !isGuest && <AuditAdmin onToast={showToast} />}
      {section === 'ai-review' && !isGuest && <AiLogReviewAdmin onToast={showToast} />}
      {section === 'visibility' && !isGuest && <PageVisibilityAdmin onToast={showToast} />}
      {section === 'branding' && !isGuest && <BrandingAdmin onToast={showToast} />}
    </div>
  );
}

function NavBtn({ active, onClick, children }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={
        active
          ? 'px-3 py-1.5 rounded-md bg-ink-800 text-accent border border-accent/40'
          : 'px-3 py-1.5 rounded-md text-ink-400 hover:text-ink-100 border border-transparent'
      }
    >
      {children}
    </button>
  );
}

function AdminCard({ title, children, onClick }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="card p-5 text-left hover:border-accent/40 transition-colors"
    >
      <h2 className="text-lg text-ink-100 font-semibold mb-2">{title}</h2>
      <p className="text-sm text-ink-400">{children}</p>
    </button>
  );
}

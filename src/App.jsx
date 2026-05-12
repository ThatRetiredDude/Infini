import { useEffect, useState, useCallback, lazy, Suspense } from 'react';
import AuthModal from './components/AuthModal.jsx';
import ChangePasswordGate from './components/ChangePasswordGate.jsx';
import DataRoomIndex from './components/DataRoomIndex.jsx';
import HomePage from './pages/Home.jsx';
import BlogList from './pages/Blog.jsx';
import BlogPost from './pages/BlogPost.jsx';
import Donations from './pages/Donations.jsx';
import { fetchMe } from './lib/api.js';

const AdminShell = lazy(() => import('./admin/AdminShell.jsx'));

const ROUTES = {
  HOME: 'home',
  BLOG: 'blog',
  BLOG_POST: 'blog-post',
  DONATIONS: 'donations',
  ADMIN: 'admin',
};

function parsePath(pathname) {
  if (pathname.startsWith('/admin'))
    return { route: ROUTES.ADMIN, params: { sub: pathname.slice(7) || '' } };
  if (pathname === '/blog' || pathname === '/blog/') return { route: ROUTES.BLOG, params: {} };
  if (pathname.startsWith('/blog/'))
    return { route: ROUTES.BLOG_POST, params: { slug: pathname.slice(6) } };
  if (pathname === '/donations') return { route: ROUTES.DONATIONS, params: {} };
  return { route: ROUTES.HOME, params: {} };
}

function normalizePagesVisibility(payload) {
  const pages = payload?.pages || payload || {};
  return {
    home: pages.home || 'public',
    blog: pages.blog || 'public',
    donations: pages.donations || 'public',
  };
}

function pageAllowed(pageKey, pagesVisibility, user) {
  const v = pagesVisibility[pageKey] || 'public';
  const admin = Boolean(user?.role === 'admin' || user?.is_admin);
  if (v === 'public') return true;
  if (admin) return true;
  if (v === 'hidden' || v === 'admin_only') return false;
  return true;
}

function PageMuted({ navigate, title }) {
  return (
    <div className="max-w-lg mx-auto px-4 py-20">
      <div className="card p-8 text-center space-y-3">
        <h1 className="text-xl text-ink-100">{title}</h1>
        <p className="text-ink-400 text-sm">
          This route is not available under the current visibility policy. Administrators can preview it
          after signing in.
        </p>
        <button type="button" className="btn-primary" onClick={() => navigate('/')}>
          Go home
        </button>
      </div>
    </div>
  );
}

export default function App() {
  const [user, setUser] = useState(null);
  const [authChecked, setAuthChecked] = useState(false);
  const [authOpen, setAuthOpen] = useState(false);
  const [pagesVisibility, setPagesVisibility] = useState({
    home: 'public',
    blog: 'public',
    donations: 'public',
  });
  const [route, setRoute] = useState(() => parsePath(window.location.pathname));

  const navigate = useCallback((path) => {
    window.history.pushState({}, '', path);
    setRoute(parsePath(path));
  }, []);

  useEffect(() => {
    const onPop = () => setRoute(parsePath(window.location.pathname));
    window.addEventListener('popstate', onPop);
    return () => window.removeEventListener('popstate', onPop);
  }, []);

  useEffect(() => {
    fetchMe()
      .then((data) => setUser(data.user))
      .catch(() => setUser(null))
      .finally(() => setAuthChecked(true));
  }, []);

  useEffect(() => {
    fetch('/api/site/visibility', { credentials: 'include' })
      .then((r) => r.json())
      .then((data) => setPagesVisibility(normalizePagesVisibility(data)))
      .catch(() => {});
  }, []);

  return (
    <div className="min-h-full flex flex-col">
      <header className="border-b border-ink-700 bg-ink-900/80 backdrop-blur sticky top-0 z-30">
        <div className="max-w-6xl mx-auto px-4 py-3 flex items-center gap-4">
          <button
            type="button"
            onClick={() => navigate('/')}
            className="font-mono text-lg font-semibold text-accent hover:text-accent-glow"
          >
            Infini
          </button>
          <nav className="flex items-center gap-1 ml-2 text-sm">
            {pageAllowed('blog', pagesVisibility, user) && (
              <NavLink current={route.route} target={ROUTES.BLOG} onClick={() => navigate('/blog')}>
                Blog
              </NavLink>
            )}
            {pageAllowed('donations', pagesVisibility, user) && (
              <NavLink
                current={route.route}
                target={ROUTES.DONATIONS}
                onClick={() => navigate('/donations')}
              >
                Donations
              </NavLink>
            )}
          </nav>
          <div className="ml-auto flex items-center gap-2 text-sm">
            {authChecked && user ? (
              <>
                {(user.role === 'admin' || user.is_admin) && !user.password_change_required && (
                  <button type="button" className="btn-ghost" onClick={() => navigate('/admin')}>
                    Admin
                  </button>
                )}
                <span className="text-ink-300 hidden sm:inline">{user.username}</span>
                <button
                  type="button"
                  className="btn-ghost"
                  onClick={async () => {
                    await fetch('/api/auth/logout', { method: 'POST', credentials: 'include' });
                    setUser(null);
                    navigate('/');
                  }}
                >
                  Sign out
                </button>
              </>
            ) : (
              <button type="button" className="btn-ghost" onClick={() => setAuthOpen(true)}>
                Sign in
              </button>
            )}
          </div>
        </div>
      </header>

      <main className="flex-1">
        {route.route === ROUTES.HOME &&
          (pageAllowed('home', pagesVisibility, user) ? (
            <HomePage navigate={navigate} />
          ) : (
            <PageMuted navigate={navigate} title="Home unavailable" />
          ))}
        {route.route === ROUTES.BLOG &&
          (pageAllowed('blog', pagesVisibility, user) ? (
            <BlogList navigate={navigate} />
          ) : (
            <PageMuted navigate={navigate} title="Blog unavailable" />
          ))}
        {route.route === ROUTES.BLOG_POST &&
          (pageAllowed('blog', pagesVisibility, user) ? (
            <BlogPost slug={route.params.slug} navigate={navigate} />
          ) : (
            <PageMuted navigate={navigate} title="Blog unavailable" />
          ))}
        {route.route === ROUTES.DONATIONS &&
          (pageAllowed('donations', pagesVisibility, user) ? (
            <Donations />
          ) : (
            <PageMuted navigate={navigate} title="Donations unavailable" />
          ))}
        {route.route === ROUTES.ADMIN && !(user?.password_change_required) && (
          <Suspense
            fallback={
              <div className="max-w-6xl mx-auto p-16 text-center text-ink-400 text-sm">
                Loading admin console…
              </div>
            }
          >
            <AdminShell
              user={user}
              authChecked={authChecked}
              onRequireLogin={() => setAuthOpen(true)}
              sub={route.params.sub}
              navigate={navigate}
            />
          </Suspense>
        )}
        {route.route === ROUTES.ADMIN && user?.password_change_required && (
          <div className="max-w-lg mx-auto px-4 py-20 text-center text-ink-400 text-sm">
            Set your administrator password using the prompt above before opening the console.
          </div>
        )}
      </main>

      <footer className="border-t border-ink-700 bg-ink-900/60">
        <div className="max-w-6xl mx-auto px-4 py-6 text-xs text-ink-400 flex flex-wrap items-center justify-between gap-2">
          <span className="font-mono">Infini · MI</span>
          <span>Access may be logged for compliance and security review.</span>
        </div>
      </footer>

      <AuthModal
        open={authOpen}
        onClose={() => setAuthOpen(false)}
        onAuthed={(u) => {
          setUser(u);
          setAuthOpen(false);
        }}
      />

      {user?.password_change_required && (
        <ChangePasswordGate
          user={user}
          onSuccess={(updated) => setUser(updated)}
          onSignedOut={() => {
            setUser(null);
            navigate('/');
          }}
        />
      )}

      <DataRoomIndex />
    </div>
  );
}

function NavLink({ current, target, onClick, children }) {
  const active = current === target;
  return (
    <button
      type="button"
      onClick={onClick}
      className={
        active
          ? 'px-3 py-1 rounded-md bg-ink-800 text-ink-100 border border-ink-600'
          : 'px-3 py-1 rounded-md text-ink-300 hover:bg-ink-800 hover:text-ink-100 border border-transparent'
      }
    >
      {children}
    </button>
  );
}

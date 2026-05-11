import { useEffect, useState, useCallback } from 'react';
import AuthModal from './components/AuthModal.jsx';
import HoneypotBait from './components/HoneypotBait.jsx';
import HomePage from './pages/Home.jsx';
import BlogList from './pages/Blog.jsx';
import BlogPost from './pages/BlogPost.jsx';
import Donations from './pages/Donations.jsx';
import AdminShell from './admin/AdminShell.jsx';
import { fetchMe } from './lib/api.js';

const ROUTES = {
  HOME: 'home',
  BLOG: 'blog',
  BLOG_POST: 'blog-post',
  DONATIONS: 'donations',
  ADMIN: 'admin',
};

function parsePath(pathname) {
  if (pathname.startsWith('/admin')) return { route: ROUTES.ADMIN, params: { sub: pathname.slice(7) || '' } };
  if (pathname === '/blog' || pathname === '/blog/') return { route: ROUTES.BLOG, params: {} };
  if (pathname.startsWith('/blog/')) return { route: ROUTES.BLOG_POST, params: { slug: pathname.slice(6) } };
  if (pathname === '/donations') return { route: ROUTES.DONATIONS, params: {} };
  return { route: ROUTES.HOME, params: {} };
}

export default function App() {
  const [user, setUser] = useState(null);
  const [authChecked, setAuthChecked] = useState(false);
  const [authOpen, setAuthOpen] = useState(false);
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

  return (
    <div className="min-h-full flex flex-col">
      <header className="border-b border-ink-700 bg-ink-900/80 backdrop-blur sticky top-0 z-30">
        <div className="max-w-6xl mx-auto px-4 py-3 flex items-center gap-4">
          <button
            type="button"
            onClick={() => navigate('/')}
            className="font-mono text-lg font-semibold text-accent hover:text-accent-glow"
          >
            InfiniPot
          </button>
          <nav className="flex items-center gap-1 ml-2 text-sm">
            <NavLink current={route.route} target={ROUTES.BLOG} onClick={() => navigate('/blog')}>
              Blog
            </NavLink>
            <NavLink current={route.route} target={ROUTES.DONATIONS} onClick={() => navigate('/donations')}>
              Donations
            </NavLink>
          </nav>
          <div className="ml-auto flex items-center gap-2 text-sm">
            {authChecked && user ? (
              <>
                {(user.role === 'admin' || user.is_admin) && (
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
        {route.route === ROUTES.HOME && <HomePage navigate={navigate} />}
        {route.route === ROUTES.BLOG && <BlogList navigate={navigate} />}
        {route.route === ROUTES.BLOG_POST && <BlogPost slug={route.params.slug} navigate={navigate} />}
        {route.route === ROUTES.DONATIONS && <Donations />}
        {route.route === ROUTES.ADMIN && (
          <AdminShell
            user={user}
            authChecked={authChecked}
            onRequireLogin={() => setAuthOpen(true)}
            sub={route.params.sub}
            navigate={navigate}
          />
        )}
      </main>

      <footer className="border-t border-ink-700 bg-ink-900/60">
        <div className="max-w-6xl mx-auto px-4 py-6 text-xs text-ink-400 flex flex-wrap items-center justify-between gap-2">
          <span className="font-mono">InfiniPot · MI</span>
          <span>Automated access is logged. Read the access policy for details.</span>
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

      {/* Hidden bait for crawlers and AI agents. Invisible to real users. */}
      <HoneypotBait />
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

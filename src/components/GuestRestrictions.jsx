import { useEffect } from 'react';

/**
 * GuestRestrictions — applied when the logged-in user has role === 'guest'.
 * Disables text selection, copy/cut/paste globally on the document for demo purposes.
 * Also hides export-related buttons via a data attribute hook.
 * This is client-side defense-in-depth; server still enforces all writes/exports.
 */
export default function GuestRestrictions() {
  useEffect(() => {
    const root = document.documentElement;
    const prevUserSelect = root.style.userSelect;
    root.style.userSelect = 'none';

    const prevent = (e) => {
      e.preventDefault();
      return false;
    };

    const handleCopy = (e) => prevent(e);
    const handleCut = (e) => prevent(e);
    const handlePaste = (e) => prevent(e);
    const handleSelectStart = (e) => {
      // allow selection inside inputs/textareas for usability (e.g. search), but not content
      const tag = (e.target && e.target.tagName) || '';
      if (['INPUT', 'TEXTAREA'].includes(tag)) return;
      e.preventDefault();
    };

    document.addEventListener('copy', handleCopy, true);
    document.addEventListener('cut', handleCut, true);
    document.addEventListener('paste', handlePaste, true);
    document.addEventListener('selectstart', handleSelectStart, true);

    // Mark body so CSS can hide export buttons if desired
    document.body.setAttribute('data-guest-demo', 'true');

    return () => {
      root.style.userSelect = prevUserSelect || '';
      document.removeEventListener('copy', handleCopy, true);
      document.removeEventListener('cut', handleCut, true);
      document.removeEventListener('paste', handlePaste, true);
      document.removeEventListener('selectstart', handleSelectStart, true);
      document.body.removeAttribute('data-guest-demo');
    };
  }, []);

  return null;
}

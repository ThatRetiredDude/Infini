import DOMPurify from 'dompurify';

/**
 * Conservative allow-list for TipTap / Starter-kit–style HTML. No inline styles (`style=`)
 * to reduce XSS surface; admins still control content.
 */
const CONFIG = {
  ALLOWED_TAGS: [
    'a',
    'b',
    'blockquote',
    'br',
    'code',
    'div',
    'em',
    'h1',
    'h2',
    'h3',
    'hr',
    'i',
    'img',
    'li',
    'ol',
    'p',
    'pre',
    'span',
    'strong',
    'sub',
    'sup',
    'table',
    'tbody',
    'td',
    'th',
    'thead',
    'tr',
    'ul',
    'strike',
    'del',
    'u',
  ],
  ALLOWED_ATTR: ['href', 'src', 'alt', 'title', 'class', 'colspan', 'rowspan', 'target', 'rel'],
};

/** @param {string} html */
export function sanitizeBlogHtml(html) {
  return DOMPurify.sanitize(html || '', CONFIG);
}

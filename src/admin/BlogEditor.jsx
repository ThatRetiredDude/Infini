import { useEffect, useRef } from 'react';
import { useEditor, EditorContent } from '@tiptap/react';
import StarterKit from '@tiptap/starter-kit';
import Placeholder from '@tiptap/extension-placeholder';
import Link from '@tiptap/extension-link';
import Image from '@tiptap/extension-image';

export default function BlogEditor({ html, onChange }) {
  const editor = useEditor({
    extensions: [
      StarterKit,
      Placeholder.configure({ placeholder: 'Write the post…' }),
      Link.configure({ openOnClick: false }),
      Image.configure({ allowBase64: false, HTMLAttributes: { class: 'rounded border border-ink-700 max-w-full h-auto' } }),
    ],
    content: html || '',
    editorProps: {
      attributes: {
        class:
          'max-w-none min-h-[240px] px-4 py-3 focus:outline-none text-ink-200 text-sm leading-relaxed space-y-2',
      },
    },
    onUpdate: ({ editor: ed }) => {
      if (typeof onChange === 'function') onChange(ed.getHTML());
    },
  });

  const fileInputRef = useRef(null);

  async function insertImage() {
    if (!editor || !fileInputRef.current) return;
    fileInputRef.current.click();
  }

  async function handleImageSelected(e) {
    const file = e.target.files?.[0];
    if (!file || !editor) return;
    try {
      const form = new window.FormData();
      form.append('file', file);
      const csrf = document.cookie.split(';').find(c => c.trim().startsWith('mi_csrf='))?.split('=')[1] || '';
      const headers = csrf ? { 'X-CSRF-Token': decodeURIComponent(csrf) } : {};
      const res = await fetch('/api/admin/uploads', {
        method: 'POST',
        credentials: 'include',
        headers,
        body: form,
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data?.error || 'upload_failed');
      const url = data?.url;
      if (url) editor.chain().focus().setImage({ src: url }).run();
    } catch (err) {
      window.alert('Upload failed: ' + (err.message || err));
    } finally {
      e.target.value = '';
    }
  }

  useEffect(() => {
    if (!editor) return;
    const cur = editor.getHTML();
    const next = html || '';
    if (next !== cur) editor.commands.setContent(next, false);
  }, [editor, html]);

  if (!editor) {
    return (
      <div className="rounded-lg border border-ink-600 bg-ink-900 p-8 text-ink-500 text-sm">
        Loading editor…
      </div>
    );
  }

  return (
    <div className="rounded-lg border border-ink-600 bg-ink-950 overflow-hidden">
      <div className="flex flex-wrap gap-1 px-3 py-2 border-b border-ink-700 bg-ink-900/80">
        <button type="button" className="btn-ghost text-xs py-1" onClick={() => editor.chain().focus().toggleBold().run()}>Bold</button>
        <button type="button" className="btn-ghost text-xs py-1" onClick={() => editor.chain().focus().toggleItalic().run()}>Italic</button>
        <button type="button" className="btn-ghost text-xs py-1" onClick={() => editor.chain().focus().toggleStrike().run()}>Strike</button>
        <button type="button" className="btn-ghost text-xs py-1" onClick={() => editor.chain().focus().toggleCode().run()}>Code</button>
        <button type="button" className="btn-ghost text-xs py-1" onClick={() => editor.chain().focus().toggleHeading({ level: 1 }).run()}>H1</button>
        <button type="button" className="btn-ghost text-xs py-1" onClick={() => editor.chain().focus().toggleHeading({ level: 2 }).run()}>H2</button>
        <button type="button" className="btn-ghost text-xs py-1" onClick={() => editor.chain().focus().toggleHeading({ level: 3 }).run()}>H3</button>
        <button type="button" className="btn-ghost text-xs py-1" onClick={() => editor.chain().focus().toggleBulletList().run()}>UL</button>
        <button type="button" className="btn-ghost text-xs py-1" onClick={() => editor.chain().focus().toggleOrderedList().run()}>OL</button>
        <button type="button" className="btn-ghost text-xs py-1" onClick={() => editor.chain().focus().toggleBlockquote().run()}>Quote</button>
        <button type="button" className="btn-ghost text-xs py-1" onClick={() => editor.chain().focus().toggleCodeBlock().run()}>CodeBlock</button>
        <button type="button" className="btn-ghost text-xs py-1" onClick={() => editor.chain().focus().setHorizontalRule().run()}>HR</button>
        <button type="button" className="btn-ghost text-xs py-1" onClick={() => {
          const u = typeof window !== 'undefined' ? window.prompt('Link URL') : '';
          if (u) editor.chain().focus().setLink({ href: u }).run();
        }}>Link</button>
        <button type="button" className="btn-ghost text-xs py-1" onClick={insertImage}>Image</button>
      </div>
      <input ref={fileInputRef} type="file" accept="image/*" className="hidden" onChange={handleImageSelected} />
      <EditorContent editor={editor} />
    </div>
  );
}

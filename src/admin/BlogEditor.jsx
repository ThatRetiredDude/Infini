import { useEffect } from 'react';
import { useEditor, EditorContent } from '@tiptap/react';
import StarterKit from '@tiptap/starter-kit';
import Placeholder from '@tiptap/extension-placeholder';
import Link from '@tiptap/extension-link';

export default function BlogEditor({ html, onChange }) {
  const editor = useEditor({
    extensions: [
      StarterKit,
      Placeholder.configure({ placeholder: 'Write the post…' }),
      Link.configure({ openOnClick: false }),
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
        <button
          type="button"
          className="btn-ghost text-xs py-1"
          onClick={() => editor.chain().focus().toggleBold().run()}
        >
          Bold
        </button>
        <button
          type="button"
          className="btn-ghost text-xs py-1"
          onClick={() => editor.chain().focus().toggleItalic().run()}
        >
          Italic
        </button>
        <button
          type="button"
          className="btn-ghost text-xs py-1"
          onClick={() => editor.chain().focus().toggleCode().run()}
        >
          Code
        </button>
        <button
          type="button"
          className="btn-ghost text-xs py-1"
          onClick={() => editor.chain().focus().toggleBulletList().run()}
        >
          List
        </button>
        <button
          type="button"
          className="btn-ghost text-xs py-1"
          onClick={() => editor.chain().focus().toggleHeading({ level: 2 }).run()}
        >
          H2
        </button>
        <button
          type="button"
          className="btn-ghost text-xs py-1"
          onClick={() => {
            const prev = typeof window !== 'undefined' ? window.prompt('Link URL') : '';
            if (prev) editor.chain().focus().setLink({ href: prev }).run();
          }}
        >
          Link
        </button>
      </div>
      <EditorContent editor={editor} />
    </div>
  );
}

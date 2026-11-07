'use client';

import DOMPurify from 'isomorphic-dompurify';

export function Dashboard({ html }: { html: string }) {
  const safe = DOMPurify.sanitize(html);
  return <div dangerouslySetInnerHTML={{ __html: safe }} />;
}

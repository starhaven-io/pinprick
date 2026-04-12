import type { APIRoute } from 'astro';

const getSecurityTxt = (canonicalURL: URL) => {
  // One year from build time, normalized to midnight UTC.
  const expires = new Date();
  expires.setUTCFullYear(expires.getUTCFullYear() + 1);
  expires.setUTCHours(0, 0, 0, 0);

  return `Contact: https://github.com/p-linnane/pinprick/security/advisories/new
Expires: ${expires.toISOString()}
Preferred-Languages: en
Canonical: ${canonicalURL.href}
`;
};

export const GET: APIRoute = ({ site }) => {
  const canonicalURL = new URL('.well-known/security.txt', site);
  return new Response(getSecurityTxt(canonicalURL));
};

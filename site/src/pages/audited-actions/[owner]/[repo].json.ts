import type { APIRoute } from 'astro';
import fs from 'node:fs';
import path from 'node:path';

export const prerender = false;

export const GET: APIRoute = ({ params }) => {
  const { owner, repo } = params;
  const dataDir = path.resolve('..', 'audited-actions');
  const filePath = path.join(dataDir, owner!, `${repo}.json`);

  try {
    const data = fs.readFileSync(filePath, 'utf-8');
    return new Response(data, {
      headers: {
        'Content-Type': 'application/json',
        'Cache-Control': 'public, max-age=3600',
      },
    });
  } catch {
    return new Response(JSON.stringify([]), {
      status: 404,
      headers: { 'Content-Type': 'application/json' },
    });
  }
};

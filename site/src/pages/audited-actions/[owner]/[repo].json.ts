import type { APIRoute, GetStaticPaths } from 'astro';
import fs from 'node:fs';
import path from 'node:path';

export const getStaticPaths: GetStaticPaths = () => {
  const dataDir = path.resolve('..', 'audited-actions');
  const paths: { params: { owner: string; repo: string } }[] = [];

  for (const owner of fs.readdirSync(dataDir, { withFileTypes: true })) {
    if (!owner.isDirectory()) continue;
    for (const file of fs.readdirSync(path.join(dataDir, owner.name))) {
      if (!file.endsWith('.json')) continue;
      paths.push({ params: { owner: owner.name, repo: file.replace(/\.json$/, '') } });
    }
  }

  return paths;
};

export const GET: APIRoute = ({ params }) => {
  const { owner, repo } = params;
  const dataDir = path.resolve('..', 'audited-actions');
  const filePath = path.join(dataDir, owner!, `${repo}.json`);

  try {
    const data = fs.readFileSync(filePath, 'utf-8');
    return new Response(data, {
      headers: {
        'Content-Type': 'application/json',
        // Keep in sync with public/_headers (/audited-actions/*): the catalog
        // and its .minisig must age out together or clients see transient
        // signature mismatches after a deploy.
        'Cache-Control': 'public, max-age=300, must-revalidate',
      },
    });
  } catch {
    return new Response(JSON.stringify([]), {
      status: 404,
      headers: { 'Content-Type': 'application/json' },
    });
  }
};

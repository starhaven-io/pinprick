import type { APIRoute, GetStaticPaths } from 'astro';
import fs from 'node:fs';
import path from 'node:path';

const dataDir = path.resolve('..', 'audited-actions');

const catalogFiles = (directory: string): string[] =>
  fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const entryPath = path.join(directory, entry.name);
    if (entry.isDirectory()) return catalogFiles(entryPath);
    return entry.isFile() && entry.name.endsWith('.json') ? [entryPath] : [];
  });

const validActionKey = (value: string): boolean => {
  const components = value.split('/');
  return (
    components.length >= 2 &&
    components.every((component) => component !== '.' && component !== '..' && /^[A-Za-z0-9_.-]+$/.test(component))
  );
};

export const getStaticPaths: GetStaticPaths = () =>
  catalogFiles(dataDir).map((file) => ({
    params: {
      action: path
        .relative(dataDir, file)
        .replaceAll(path.sep, '/')
        .replace(/\.json$/, ''),
    },
  }));

export const GET: APIRoute = ({ params }) => {
  const action = params.action;
  if (!action || !validActionKey(action)) {
    return new Response(JSON.stringify([]), {
      status: 404,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const filePath = path.join(dataDir, `${action}.json`);
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

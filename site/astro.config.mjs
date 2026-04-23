// @ts-check
import { defineConfig } from 'astro/config';
import cloudflare from '@astrojs/cloudflare';
import starlight from '@astrojs/starlight';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { codecovVitePlugin } from '@codecov/vite-plugin';

const __dirname = dirname(fileURLToPath(import.meta.url));
const pinprickVersion =
  readFileSync(resolve(__dirname, '../Cargo.toml'), 'utf-8').match(/^version = "(.+?)"/m)?.[1] ?? '';

// https://astro.build/config
export default defineConfig({
  site: 'https://pinprick.rs',
  adapter: cloudflare({
    prerenderEnvironment: 'node',
    imageService: 'passthrough',
  }),
  vite: {
    define: {
      __PINPRICK_VERSION__: JSON.stringify(pinprickVersion),
    },
    plugins: [
      codecovVitePlugin({
        enableBundleAnalysis: process.env.CODECOV_TOKEN !== undefined,
        bundleName: 'pinprick-site',
        uploadToken: process.env.CODECOV_TOKEN,
        gitService: 'github',
        telemetry: false,
        uploadOverrides: {
          compareSha: process.env.GH_COMPARE_SHA,
        },
      }),
    ],
  },
  redirects: {
    '/': '/getting-started/introduction/',
  },
  integrations: [
    starlight({
      title: 'pinprick',
      description: 'GitHub Actions supply chain security.',
      favicon: '/favicon.svg',
      customCss: ['./src/styles/custom.css'],
      components: {
        SocialIcons: './src/components/SocialIcons.astro',
      },
      editLink: {
        baseUrl: 'https://github.com/starhaven-io/pinprick/edit/main/site/',
      },
      social: [
        {
          icon: 'github',
          label: 'GitHub',
          href: 'https://github.com/starhaven-io/pinprick',
        },
      ],
      sidebar: [
        {
          label: 'Getting Started',
          items: [
            { label: 'Introduction', slug: 'getting-started/introduction' },
            { label: 'Installation', slug: 'getting-started/installation' },
          ],
        },
        {
          label: 'Commands',
          items: [
            { label: 'audit', slug: 'commands/audit' },
            { label: 'clean', slug: 'commands/clean' },
            { label: 'pin', slug: 'commands/pin' },
            { label: 'update', slug: 'commands/update' },
          ],
        },
        {
          label: 'Configuration',
          items: [
            { label: 'Config File', slug: 'configuration/config-file' },
            { label: 'Audited Actions', slug: 'configuration/audited-actions' },
          ],
        },
        {
          label: 'Reference',
          items: [{ label: 'Detections', slug: 'reference/detections' }],
        },
      ],
    }),
  ],
});

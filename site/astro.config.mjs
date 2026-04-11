// @ts-check
import { defineConfig } from 'astro/config';
import cloudflare from '@astrojs/cloudflare';
import starlight from '@astrojs/starlight';

// https://astro.build/config
export default defineConfig({
  site: 'https://pinprick.rs',
  adapter: cloudflare({
    prerenderEnvironment: 'node',
    imageService: 'passthrough',
  }),
  integrations: [
    starlight({
      title: 'pinprick',
      description: 'GitHub Actions supply chain security.',
      favicon: '/favicon.svg',
      customCss: ['./src/styles/custom.css'],
      editLink: {
        baseUrl: 'https://github.com/p-linnane/pinprick/edit/main/site/',
      },
      social: [
        {
          icon: 'github',
          label: 'GitHub',
          href: 'https://github.com/p-linnane/pinprick',
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
            { label: 'pin', slug: 'commands/pin' },
            { label: 'update', slug: 'commands/update' },
            { label: 'audit', slug: 'commands/audit' },
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

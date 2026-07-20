# Starlight Starter Kit: Basics

[![Built with Starlight](https://astro.badg.es/v2/built-with-starlight/tiny.svg)](https://starlight.astro.build)

```
npm create astro@latest -- --template starlight
```

> 🧑‍🚀 **Seasoned astronaut?** Delete this file. Have fun!

## 🚀 Project Structure

Inside of your Astro + Starlight project, you'll see the following folders and files:

```
.
├── public/
├── src/
│   ├── assets/
│   ├── content/
│   │   └── docs/
│   └── content.config.ts
├── astro.config.mjs
├── package.json
└── tsconfig.json
```

Starlight looks for `.md` or `.mdx` files in the `src/content/docs/` directory. Each file is exposed as a route based on its file name.

Images can be added to `src/assets/` and embedded in Markdown with a relative link.

Static assets, like favicons, can be placed in the `public/` directory.

## 🧞 Commands

All commands are run from the root of the project, from a terminal:

| Command                         | Action                                           |
| :------------------------------ | :----------------------------------------------- |
| `npm ci --strict-allow-scripts` | Installs dependencies                            |
| `npm run dev`                   | Starts local dev server at `localhost:4321`      |
| `npm run build`                 | Build your production site to `./dist/`          |
| `npm run preview`               | Preview your build locally, before deploying     |
| `npm run astro ...`             | Run CLI commands like `astro add`, `astro check` |
| `npm run astro -- --help`       | Get help using the Astro CLI                     |

The site denies its current dependency install scripts. Run `just npm-policy`
from the repository root to verify that every locked install script is either
denied or approved only for an exact version.

## 👀 Want to learn more?

Check out [Starlight’s docs](https://starlight.astro.build/), read [the Astro documentation](https://docs.astro.build), or jump into the [Astro Discord server](https://astro.build/chat).

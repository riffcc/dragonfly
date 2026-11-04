# Dragonfly Website

This directory contains the Hugo/Hextra website for https://dragonfly.computer,
including product pages and documentation. Update it alongside the code it describes.

## Local development

Install Hugo Extended 0.147.7 and Go 1.22 or later, then run from this directory:

```sh
hugo server
```

Build the production site with `hugo --gc --minify`. Generated `public/` and
`resources/` files are ignored. Commit `go.sum` when changing theme dependencies.

## Cloudflare Pages

Connect `riffcc/dragonfly` using the Pages Git integration:

| Setting | Value |
| --- | --- |
| Production branch | `main` |
| Root directory | `docs` |
| Build command | `hugo --gc --minify` |
| Build output directory | `public` |
| `HUGO_VERSION` | `0.147.7` |
| Build watch include paths | `docs/*` |

Use the same build settings for production and branch previews. The canonical URL
is configured in `hugo.yaml`; moving the source directory does not change URLs.
The root repository's Website workflow checks builds and retains the output as an
artifact. Cloudflare handles deployment through its Git integration without a
GitHub API token secret.

Before changing DNS, verify the Pages preview homepage, documentation, search,
images, and a missing URL. Add `dragonfly.computer` through Pages custom domains
and follow its DNS instructions. Keep the previous hosting available until HTTPS
and the production domain are verified; retain the prior DNS values for rollback.

The source was imported from `riffcc/dragonflycomputer.github.io` using Git subtree
with its history preserved. The old repository should stop publishing only after
the custom domain has been verified on Cloudflare.

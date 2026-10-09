# Agentic Integration Hub

Independent knowledge, tools and research website.

## Deploy using Cloudflare Pages

- GitHub repository: `rameshvaranganti/agentic-integration-hub`
- Production branch: `main`
- Framework preset: None
- Build command: leave blank
- Build output directory: `public`

Upload all contents from `public/` into the repository `public/` directory. Commit to `main`; Cloudflare Pages automatically deploys.

## Project files

- `public/index.html` is the homepage.
- `public/assets/styles.css` is the shared responsive stylesheet.
- `public/assets/site.js` contains navigation, search/filter and browser-side tool logic.
- Other `public/*.html` files are topic pages.
- `public/articles/` contains four substantive starter guides.
- `public/disclaimer.html` contains the vendor independence statement.

## Security

Do not commit secrets or customer payloads. Browser tools are for sample data. The website does not include a production AI backend or live MCP server.

## Custom domain

`agenticintegrationhub.com` is already connected to Cloudflare Pages. Do not overwrite Hostinger email MX, SPF, DKIM, or DMARC DNS records. Configure `www` and `.si` redirects separately.

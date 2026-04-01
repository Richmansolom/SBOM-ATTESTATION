# Free Hosting Setup (GitHub Pages + Render)

This project can run with a free frontend and free backend:

- Frontend (Mission Control UI): GitHub Pages
- Backend API (`/api/*`): Render free web service

## 1) Deploy API for free on Render

1. Sign in to [Render](https://render.com/).
2. Create a **New Web Service** from this GitHub repo.
3. Render auto-detects `render.yaml` (or set manually):
   - Build: `pip install -r sbom_ui/requirements.txt`
   - Start: `gunicorn --chdir sbom_ui app:app`
4. Wait until service is live, note URL, e.g.:
   - `https://sbom-control-api.onrender.com`

## 2) Deploy frontend for free on GitHub Pages

This repo includes `.github/workflows/pages-ui.yml`, which deploys `sbom_ui/static/` to Pages.

1. In GitHub repo: **Settings -> Pages**
2. Source: **GitHub Actions**
3. Push to `main` (or run workflow manually).
4. Open Pages URL shown in workflow output.

## 3) Point frontend to backend API

The frontend supports runtime API base URL selection:

- Default behavior on GitHub Pages now auto-targets:
  - `https://sbom-control-api.onrender.com`
- If your backend URL is different, override once with:
- Append `?api=<backend-url>` to the Pages URL once:
  - `https://<user>.github.io/<repo>/?api=https://sbom-control-api.onrender.com`
- This value is stored in browser localStorage (`sbom_api_base`) and reused.
- You can also set/update this in the UI Connect modal using `API Base URL`.

To change API later, use a new `?api=...` value once.

## 4) Optional custom domain

After Pages works, you can map your domain/subdomain to GitHub Pages.

Important:

- If you previously added `127.0.0.1 www.sbomcontrol.com` to your local hosts file for local testing, remove it for public-domain testing.
- That local mapping forces the domain to your computer and can produce `ERR_CONNECTION_REFUSED` when your local Flask app is not running.

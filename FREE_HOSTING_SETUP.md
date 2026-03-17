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

- Append `?api=<backend-url>` to the Pages URL once:
  - `https://<user>.github.io/<repo>/?api=https://sbom-control-api.onrender.com`
- This value is stored in browser localStorage (`sbom_api_base`) and reused.

To change API later, use a new `?api=...` value once.

## 4) Optional custom domain

After Pages works, you can map your domain/subdomain to GitHub Pages.

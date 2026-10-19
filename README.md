# Qishing Backend

FastAPI service for auditing URLs for phishing indicators. The service loads
the required `top-1m.csv` domain dataset during startup.

## Deploy to Render

1. Push this project to a Git repository, including `top-1m.csv`.
2. In Render, create a new **Blueprint** and select that repository.
3. Render reads `render.yaml` to install dependencies, start the API, and
   configure its health check.
4. Once the deploy is live, open `/docs` on the service URL to view the API.

The health check is available at `/health`. URL audits are available at
`POST /api/v1/audit-url` with a JSON body such as `{"url":"https://example.com"}`.

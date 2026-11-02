# Property Tools Portal

One front door linking the three Cloud Run tools (Capital / Expense /
Incident). The tools keep their own addresses; this page just directs people.

Tool URLs are baked in as defaults; override with env vars CAPITAL_URL,
EXPENSE_URL, INCIDENT_URL (and COMPANY_NAME) if a service address ever changes.

Deploy:
    gcloud run deploy portal --source . --project capital-processor --region us-central1 --allow-unauthenticated --max-instances 1 --memory 256Mi

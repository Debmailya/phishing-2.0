import httpx

from app.core.config import settings


async def google_safe_browsing_lookup(url: str) -> bool:
    if not settings.google_safe_browsing_api_key:
        return False

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={settings.google_safe_browsing_api_key}"
    payload = {
        "client": {"clientId": "phishguard-enterprise", "clientVersion": "2.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    async with httpx.AsyncClient(timeout=4.0) as client:
        response = await client.post(endpoint, json=payload)
        response.raise_for_status()
        return bool(response.json().get("matches"))

import os
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from typing import List, Optional
import requests
from database import create_document
from schemas import Check, Breach

app = FastAPI(title="BreachGuard API", description="Check if an email appears in public breaches", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class EmailCheckRequest(BaseModel):
    email: EmailStr

class EmailCheckResponse(BaseModel):
    email: EmailStr
    found: bool
    count: int
    breaches: List[Breach] = []
    source: str
    is_demo: bool

@app.get("/")
def read_root():
    return {"message": "BreachGuard backend is running"}

@app.post("/api/check", response_model=EmailCheckResponse)
def check_email_breaches(payload: EmailCheckRequest):
    """
    Check an email against breach sources. Uses HaveIBeenPwned-compatible public demo endpoint if API key not set.
    Persists the check result to database.
    """
    email = payload.email

    # Determine source and endpoint
    hibp_key = os.getenv("HIBP_API_KEY")
    is_demo = False

    headers = {"User-Agent": "BreachGuard/1.0"}

    if hibp_key:
        # Official HIBP API (requires key). Endpoint: https://haveibeenpwned.com/api/v3/breachedaccount/{account}
        # Note: HIBP requires k-Anonymity headers; here we call the breaches endpoint for accounts.
        headers.update({"hibp-api-key": hibp_key})
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
        params = {"truncateResponse": "false"}
    else:
        # Fallback to a mock/demo dataset hosted on GitHub gist or static JSON for demo
        # We'll simulate no external call by returning an empty list for unknown emails
        url = None
        is_demo = True

    breaches: List[Breach] = []

    try:
        if url:
            resp = requests.get(url, headers=headers, params=params, timeout=12)
            if resp.status_code == 404:
                breaches_raw = []
            elif resp.ok:
                breaches_raw = resp.json()
            else:
                raise HTTPException(status_code=resp.status_code, detail=resp.text[:200])
        else:
            # Demo behavior: return a sample breach for recognizable domains
            domain = email.split("@")[-1].lower()
            if domain in {"example.com", "test.com"}:
                breaches_raw = [
                    {
                        "Name": "ExampleBreach",
                        "Domain": domain,
                        "BreachDate": "2023-09-10",
                        "AddedDate": "2023-10-01",
                        "PwnCount": 12345,
                        "Description": "Sample demo breach to showcase UI.",
                        "DataClasses": ["Email addresses", "Passwords"],
                        "IsVerified": True,
                    }
                ]
            else:
                breaches_raw = []

        # Normalize to our Breach schema field names (lower camel to our snake-like)
        for b in breaches_raw:
            breaches.append(
                Breach(
                    name=b.get("Name") or b.get("name") or "Unknown",
                    domain=b.get("Domain") or b.get("domain"),
                    breachDate=b.get("BreachDate") or b.get("breachDate"),
                    addedDate=b.get("AddedDate") or b.get("addedDate"),
                    pwnCount=b.get("PwnCount") or b.get("pwnCount"),
                    description=b.get("Description") or b.get("description"),
                    dataClasses=b.get("DataClasses") or b.get("dataClasses") or [],
                    isVerified=b.get("IsVerified") if b.get("IsVerified") is not None else b.get("isVerified"),
                )
            )

        result = Check(
            email=email,
            found=len(breaches) > 0,
            count=len(breaches),
            breaches=breaches,
            source="hibp" if hibp_key else "demo",
            is_demo=not bool(hibp_key),
        )

        # Persist
        try:
            create_document("check", result)
        except Exception as e:
            # Don't fail the request if DB is not available; just proceed.
            pass

        return EmailCheckResponse(
            email=email,
            found=result.found,
            count=result.count,
            breaches=result.breaches,
            source=result.source,
            is_demo=result.is_demo,
        )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)[:200])

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)

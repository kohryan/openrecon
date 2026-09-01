"""Knowledge about managed hosting platforms, shared by several collectors.

Two distinct questions, easy to conflate:

* *Who operates the address behind this hostname?* Decides whether active
  scanning is authorized - you may own the name without owning the server.
* *Is this hostname itself a tenant on a platform's public suffix?* Decides
  whether DNS-policy advice is actionable. Telling someone to publish DMARC on
  `app.vercel.app` is telling them to change a record only Vercel can change.
"""

from __future__ import annotations

# CNAME targets that mean the addresses behind a hostname belong to a platform.
MANAGED_PLATFORM_SUFFIXES: dict[str, str] = {
    "vercel-dns.com": "Vercel",
    "vercel-dns-017.com": "Vercel",
    "vercel.app": "Vercel",
    "netlify.app": "Netlify",
    "netlify.com": "Netlify",
    "github.io": "GitHub Pages",
    "herokudns.com": "Heroku",
    "herokuapp.com": "Heroku",
    "cloudfront.net": "AWS CloudFront",
    "elasticbeanstalk.com": "AWS Elastic Beanstalk",
    "azurewebsites.net": "Azure App Service",
    "azureedge.net": "Azure CDN",
    "trafficmanager.net": "Azure Traffic Manager",
    "fastly.net": "Fastly",
    "cdn.cloudflare.net": "Cloudflare",
    "pages.dev": "Cloudflare Pages",
    "workers.dev": "Cloudflare Workers",
    "short.io": "Short.io",
    "shopify.com": "Shopify",
    "myshopify.com": "Shopify",
    "squarespace.com": "Squarespace",
    "wpengine.com": "WP Engine",
    "pantheonsite.io": "Pantheon",
    "webflow.io": "Webflow",
    "readthedocs.io": "Read the Docs",
    "zendesk.com": "Zendesk",
    "statuspage.io": "Statuspage",
    "firebaseapp.com": "Firebase Hosting",
    "web.app": "Firebase Hosting",
    "storage.googleapis.com": "Google Cloud Storage",
    "freshdesk.com": "Freshdesk",
    "ghost.io": "Ghost",
}

# Suffixes a tenant is *hosted under*. The tenant controls the application but
# not the zone, so zone-level advice (SPF, DMARC, CAA, registrar locks) belongs
# to the platform, not to them.
TENANT_APEX_SUFFIXES: dict[str, str] = {
    "vercel.app": "Vercel",
    "netlify.app": "Netlify",
    "github.io": "GitHub Pages",
    "pages.dev": "Cloudflare Pages",
    "workers.dev": "Cloudflare Workers",
    "web.app": "Firebase Hosting",
    "firebaseapp.com": "Firebase Hosting",
    "herokuapp.com": "Heroku",
    "azurewebsites.net": "Azure App Service",
    "onrender.com": "Render",
    "fly.dev": "Fly.io",
    "surge.sh": "Surge",
    "glitch.me": "Glitch",
    "replit.app": "Replit",
    "streamlit.app": "Streamlit",
    "railway.app": "Railway",
    "koyeb.app": "Koyeb",
    "deno.dev": "Deno Deploy",
    "myshopify.com": "Shopify",
    "wixsite.com": "Wix",
    "readthedocs.io": "Read the Docs",
    "gitbook.io": "GitBook",
    "notion.site": "Notion",
}


def managed_platform(cname: str | None) -> str | None:
    """The third party operating the addresses behind this CNAME, if any."""
    if not cname:
        return None
    low = cname.lower()
    for suffix, platform in MANAGED_PLATFORM_SUFFIXES.items():
        if low == suffix or low.endswith(f".{suffix}") or suffix in low:
            return platform
    return None


def tenant_platform(hostname: str) -> str | None:
    """The platform whose zone this hostname is a tenant of, if any."""
    low = hostname.lower().rstrip(".")
    for suffix, platform in TENANT_APEX_SUFFIXES.items():
        if low.endswith(f".{suffix}"):
            return platform
    return None

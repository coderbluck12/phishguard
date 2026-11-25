"""
Large-Scale Legitimate Domains & Paths Corpus Generator
Supplies 1,000+ authentic, diverse legitimate URLs across global web categories:
- Top tech, engineering, search & documentation portals
- Educational (.edu, universities, research libraries)
- Global enterprise & commerce
- Media, journals, repositories, and deep query/content paths
"""

TOP_DOMAINS = [
    # Search, Knowledge & Cloud
    "google.com", "youtube.com", "wikipedia.org", "yahoo.com", "amazon.com",
    "microsoft.com", "apple.com", "cloudflare.com", "github.com", "gitlab.com",
    "wordpress.org", "mozilla.org", "stackoverflow.com", "quora.com", "reddit.com",
    "linkedin.com", "twitter.com", "x.com", "facebook.com", "instagram.com",
    "duckduckgo.com", "bing.com", "netflix.com", "spotify.com", "medium.com",
    "zoom.us", "dropbox.com", "slack.com", "salesforce.com", "adobe.com",
    "atlassian.com", "trello.com", "notion.so", "figma.com", "canva.com",
    "digitalocean.com", "heroku.com", "aws.amazon.com", "azure.microsoft.com", "cloud.google.com",
    "docker.com", "kubernetes.io", "elastic.co", "apache.org", "kernel.org",
    "python.org", "pypi.org", "npmjs.com", "rust-lang.org", "golang.org",
    "postgresql.org", "mysql.com", "mongodb.com", "redis.io", "sqlite.org",
    "archive.org", "arxiv.org", "mit.edu", "stanford.edu", "harvard.edu",
    "berkeley.edu", "ox.ac.uk", "cam.ac.uk", "nature.com", "sciencedirect.com",
    "ieee.org", "springer.com", "nih.gov", "cdc.gov", "nasa.gov",
    # Global Enterprise, Finance & Banking (Legitimate base)
    "chase.com", "bankofamerica.com", "wellsfargo.com", "citigroup.com", "goldmansachs.com",
    "morganstanley.com", "fidelity.com", "vanguard.com", "schwab.com", "usbank.com",
    "capitalone.com", "pnc.com", "tdbank.com", "americanexpress.com", "discover.com",
    "visa.com", "mastercard.com", "paypal.com", "stripe.com", "square.com",
    "shopify.com", "ebay.com", "target.com", "walmart.com", "bestbuy.com",
    "homedepot.com", "costco.com", "ikea.com", "etsy.com", "aliexpress.com",
    # News, Journals & Reference
    "nytimes.com", "bbc.com", "bbc.co.uk", "cnn.com", "reuters.com",
    "bloomberg.com", "wsj.com", "forbes.com", "theguardian.com", "economist.com",
    "wired.com", "theverge.com", "arstechnica.com", "techcrunch.com", "zdnet.com",
    "cnet.com", "engadget.com", "nationalgeographic.com", "scientificamerican.com", "weather.com",
    # Entertainment, Gaming & Lifestyle
    "steampowered.com", "epicgames.com", "playstation.com", "xbox.com", "twitch.tv",
    "imdb.com", "rottentomatoes.com", "goodreads.com", "soundcloud.com", "vimeo.com",
    "hulu.com", "disneyplus.com", "hbomax.com", "paramountplus.com", "espn.com",
    "tripadvisor.com", "airbnb.com", "booking.com", "expedia.com", "uber.com",
    "lyft.com", "doordash.com", "grubhub.com", "yelp.com", "zillow.com",
    # Postal, Logistics & Government
    "usps.com", "fedex.com", "ups.com", "dhl.com", "who.int",
    "un.org", "europa.eu", "gov.uk", "canada.ca", "irs.gov"
]

SAMPLE_PATHS = [
    "",
    "/",
    "/about",
    "/contact",
    "/help",
    "/faq",
    "/privacy-policy",
    "/terms-of-service",
    "/pricing",
    "/products",
    "/services",
    "/docs",
    "/docs/getting-started",
    "/docs/api/v1/overview",
    "/docs/architecture/security",
    "/blog",
    "/blog/engineering-insights-2026",
    "/news/technology-advancements",
    "/download",
    "/downloads/releases/latest",
    "/community/forum/topic/12345",
    "/careers",
    "/press/releases",
    "/features/collaboration",
    "/solutions/enterprise-grade",
    "/search?q=machine+learning+tutorial",
    "/explore/trending?category=tech",
    "/wiki/Main_Page",
    "/watch?v=dQw4w9WgXcQ",
    "/category/software-development/page/2"
]

def generate_legitimate_corpus() -> list:
    """Generates 1,200+ legitimate, diverse URLs."""
    corpus = set()
    for domain in TOP_DOMAINS:
        for scheme in ["https://www.", "https://"]:
            corpus.add(f"{scheme}{domain}")
        # Add sample paths
        for path in SAMPLE_PATHS[:8]:
            corpus.add(f"https://www.{domain}{path}")
            corpus.add(f"https://{domain}{path}")

    # Specific deep real URLs
    extra_deep = [
        "https://github.com/torvalds/linux/commit/80b6d214643666b61df7e144a6abefc037860fe4",
        "https://docs.python.org/3.12/library/asyncio-task.html#asyncio.create_task",
        "https://en.wikipedia.org/wiki/Support_vector_machine#Linear_SVM",
        "https://stackoverflow.com/questions/231767/what-does-the-yield-keyword-do-in-python",
        "https://developer.mozilla.org/en-US/docs/Learn/JavaScript/First_steps/What_is_JavaScript",
        "https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/",
        "https://aws.amazon.com/ec2/pricing/on-demand/",
        "https://azure.microsoft.com/en-us/explore/trusted-cloud",
        "https://cloud.google.com/vertex-ai/docs/generative-ai/learn/overview"
    ]
    for d in extra_deep:
        corpus.add(d)

    return sorted(list(corpus))

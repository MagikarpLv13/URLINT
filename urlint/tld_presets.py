from __future__ import annotations

from typing import Iterable


TLD_GROUPS = {
    "_meta": {
        "description": "Groupes prédéfinis de TLDs à tester selon région, langue, usage métier ou scénario d'analyse.",
        "source_reference": "https://data.iana.org/TLD/tlds-alpha-by-domain.txt",
        "format": "TLDs en minuscules, sans point initial.",
        "note": "Les groupes sont logiques et exploitables, pas une simple duplication brute de la racine IANA.",
    },
    "global_common": [
        "com", "net", "org", "info", "biz", "name", "pro", "int", "edu", "gov", "mil",
        "co", "io", "ai", "me", "tv", "fm", "cc", "ws", "to", "gg", "je",
    ],
    "generic_web_marketing": [
        "site", "website", "online", "space", "world", "today", "live", "life", "zone",
        "page", "link", "click", "cloud", "app", "dev", "xyz", "top", "one", "win",
        "vip", "club", "buzz", "fun", "lol", "cool", "best", "plus", "now", "new",
    ],
    "tech_dev_it": [
        "app", "dev", "software", "systems", "technology", "tech", "digital", "cloud",
        "hosting", "host", "domains", "network", "net", "computer", "codes", "data",
        "bot", "ai", "io", "it", "tools", "support", "security", "secure",
    ],
    "business_company": [
        "business", "company", "enterprises", "corp", "inc", "ltd", "llc", "llp",
        "sarl", "sas", "gmbh", "group", "holdings", "partners", "limited", "management",
        "consulting", "solutions", "services", "agency", "center", "international",
    ],
    "commerce_retail": [
        "shop", "shopping", "store", "market", "markets", "sale", "deals", "discount",
        "coupons", "coupon", "bargains", "buy", "forsale", "auction", "tienda", "boutique",
        "fashion", "shoes", "clothing", "jewelry", "beauty", "makeup", "hair",
    ],
    "finance_banking_crypto_like": [
        "bank", "finance", "financial", "capital", "cash", "fund", "investments",
        "money", "loan", "loans", "credit", "creditcard", "creditunion", "mortgage",
        "forex", "trading", "trade", "exchange", "broker", "insurance", "insure",
        "tax", "accountant", "accountants", "cpa",
    ],
    "legal_public_admin": [
        "law", "lawyer", "legal", "attorney", "abogado", "claims", "gov", "gouv",
        "republican", "democrat", "vote", "voting", "voto", "politie",
    ],
    "education_research": [
        "academy", "college", "degree", "education", "school", "schule", "study",
        "training", "university", "institute", "courses", "scholarships", "science",
        "phd", "prof", "museum",
    ],
    "health_medical": [
        "health", "healthcare", "doctor", "clinic", "dental", "dentist", "hospital",
        "surgery", "pharmacy", "physio", "care", "bio", "hiv",
    ],
    "media_content_entertainment": [
        "media", "news", "press", "blog", "video", "tube", "movie", "film", "music",
        "audio", "radio", "show", "theater", "theatre", "fans", "fan", "game", "games",
        "stream", "studio", "photos", "photo", "photography", "pics", "pictures",
    ],
    "social_community_identity": [
        "social", "community", "chat", "forum", "wiki", "review", "reviews", "feedback",
        "group", "club", "ngo", "ong", "charity", "foundation", "giving", "gives",
        "family", "mom", "kids", "gay", "lgbt",
    ],
    "travel_hospitality_places": [
        "travel", "tours", "voyage", "viajes", "flights", "fly", "cruise", "cruises",
        "hotel", "hotels", "holiday", "vacations", "camp", "cafe", "bar", "pub",
        "restaurant", "rest", "pizza", "food", "catering",
    ],
    "real_estate_construction": [
        "realestate", "realtor", "realty", "estate", "properties", "property",
        "apartments", "condos", "house", "homes", "rent", "rentals", "lease",
        "construction", "builders", "build", "contractors", "plumbing", "repair",
        "kitchen", "land",
    ],
    "jobs_careers": [
        "career", "careers", "jobs", "work", "works", "mba", "training", "consulting",
        "expert", "engineer", "engineering",
    ],
    "sports_gaming_betting": [
        "sport", "football", "soccer", "rugby", "tennis", "golf", "hockey", "basketball",
        "baseball", "cricket", "futbol", "ski", "racing", "rodeo", "poker", "bet",
        "casino", "game", "games",
    ],
    "adult_sensitive": [
        "adult", "porn", "sex", "sexy", "xxx", "dating", "singles",
    ],
    "france_francophone": [
        "fr", "re", "yt", "pm", "wf", "tf", "nc", "pf", "gp", "mq", "bl", "mf",
        "paris", "alsace", "bzh", "corsica", "eus", "cat", "quebec",
        "be", "ch", "lu", "mc", "ca", "sn", "ci", "bf", "bj", "tg", "ga", "cm",
        "cd", "cg", "mg", "ml", "ne", "rw", "bi", "dj", "sc", "vu",
    ],
    "europe": [
        "ad", "al", "am", "at", "ax", "ba", "be", "bg", "by", "ch", "cy", "cz",
        "de", "dk", "ee", "es", "eu", "fi", "fo", "fr", "gb", "gg", "gi", "gr",
        "hr", "hu", "ie", "im", "is", "it", "je", "li", "lt", "lu", "lv", "mc",
        "md", "me", "mk", "mt", "nl", "no", "pl", "pt", "ro", "rs", "ru", "se",
        "si", "sk", "sm", "su", "tr", "ua", "uk", "va",
        "alsace", "amsterdam", "barcelona", "bayern", "berlin", "brussels",
        "cologne", "corsica", "eus", "frl", "gent", "hamburg", "helsinki",
        "istanbul", "koeln", "london", "madrid", "moscow", "nrw", "paris",
        "ruhr", "saarland", "stockholm", "swiss", "tirol", "vlaanderen",
        "wales", "wien",
    ],
    "european_union_eea_core": [
        "at", "be", "bg", "hr", "cy", "cz", "dk", "ee", "fi", "fr", "de", "gr",
        "hu", "ie", "it", "lv", "lt", "lu", "mt", "nl", "pl", "pt", "ro", "sk",
        "si", "es", "se", "eu", "is", "li", "no",
    ],
    "north_america": [
        "ca", "us", "mx", "bm", "gl", "pm", "pr", "um", "gov", "mil", "edu",
        "nyc", "boston", "miami", "vegas",
    ],
    "latin_america_caribbean": [
        "ag", "ai", "ar", "aw", "bb", "bl", "bo", "bq", "br", "bs", "bz", "cl",
        "co", "cr", "cu", "cw", "dm", "do", "ec", "fk", "gd", "gf", "gp", "gt",
        "gy", "hn", "ht", "jm", "kn", "ky", "lc", "mf", "mq", "ms", "ni", "pa",
        "pe", "py", "sr", "sv", "sx", "tc", "tt", "uy", "vc", "ve", "vg", "vi",
        "lat", "latino", "rio", "tienda", "viajes", "voto",
    ],
    "africa": [
        "ac", "ao", "bf", "bi", "bj", "bw", "cd", "cf", "cg", "ci", "cm", "cv",
        "dj", "dz", "eg", "er", "et", "ga", "gh", "gm", "gn", "gq", "gw", "ke",
        "km", "lr", "ls", "ly", "ma", "mg", "ml", "mr", "mu", "mw", "mz", "na",
        "ne", "ng", "re", "rw", "sc", "sd", "sh", "sl", "sn", "so", "ss", "st",
        "sz", "td", "tg", "tn", "tz", "ug", "yt", "za", "zm", "zw",
        "africa", "capetown", "durban", "joburg",
    ],
    "middle_east_north_africa": [
        "ae", "bh", "dz", "eg", "il", "iq", "ir", "jo", "kw", "lb", "ly", "ma",
        "om", "ps", "qa", "sa", "sy", "tn", "tr", "ye", "arab", "dubai", "pars",
        "abudhabi", "shia",
    ],
    "asia": [
        "af", "az", "bd", "bn", "bt", "cc", "cn", "hk", "id", "in", "io", "jp",
        "kg", "kh", "kp", "kr", "kz", "la", "lk", "mm", "mn", "mo", "mv", "my",
        "np", "ph", "pk", "sg", "th", "tj", "tl", "tm", "tw", "uz", "vn",
        "asia", "okinawa", "osaka", "kyoto", "nagoya", "tokyo", "yokohama",
        "taipei", "ryukyu", "shiksha", "desi",
    ],
    "oceania_pacific": [
        "as", "au", "ck", "cx", "fj", "fm", "gu", "hm", "ki", "mh", "mp", "nc",
        "nf", "nr", "nu", "nz", "pf", "pg", "pn", "pw", "sb", "tk", "to", "tv",
        "vu", "wf", "ws", "melbourne", "sydney",
    ],
    "china_chinese_market": [
        "cn", "hk", "mo", "tw", "asia", "wang", "wanggou", "xin", "ren", "shouji",
        "tushu", "xihuan", "anquan", "citic", "baidu", "alibaba", "alipay", "taobao",
        "tmall", "weibo", "sina", "sohu", "unicom",
    ],
    "japan_market": [
        "jp", "tokyo", "osaka", "kyoto", "nagoya", "okinawa", "yokohama", "ryukyu",
        "sakura", "jprs", "nissan", "toyota", "honda", "suzuki", "datsun", "yodobashi",
    ],
    "india_south_asia": [
        "in", "bd", "lk", "np", "pk", "bt", "mv", "shiksha", "desi",
    ],
    "security_triage_high_signal": [
        "com", "net", "org", "info", "biz", "co", "io", "ai", "me", "cc", "tv",
        "xyz", "top", "site", "online", "shop", "store", "vip", "club", "live",
        "click", "link", "cloud", "app", "dev", "support", "help", "service",
        "services", "email", "download", "zip", "mov", "cam", "icu", "cyou", "cfd",
    ],
    "lookalike_brand_risk_common": [
        "com", "net", "org", "co", "io", "ai", "app", "dev", "cloud", "online",
        "site", "shop", "store", "support", "help", "service", "services", "email",
        "login", "secure", "security", "accountants", "bank", "finance", "pay",
        "zip", "mov", "vip", "top", "xyz", "click", "link",
    ],
    "brand_tlds_often_not_registerable_publicly": [
        "google", "goog", "gmail", "youtube", "android", "apple", "amazon", "aws",
        "microsoft", "windows", "xbox", "azure", "bmw", "audi", "volvo", "toyota",
        "honda", "nissan", "samsung", "sony", "canon", "nikon", "dell", "cisco",
        "oracle", "sap", "ibm", "intel", "netflix", "bbc", "fox", "visa", "amex",
        "barclays", "hsbc", "bnpparibas", "sncf", "orange", "ovh",
    ],
    "idn_punycode_all_from_iana_prefix": [
        "xn--11b4c3d", "xn--1ck2e1b", "xn--1qqw23a", "xn--2scrj9c",
        "xn--30rr7y", "xn--3bst00m", "xn--3ds443g", "xn--3e0b707e",
        "xn--3hcrj9c", "xn--3pxu8k", "xn--42c2d9a", "xn--45br5cyl",
        "xn--45brj9c", "xn--45q11c", "xn--4dbrk0ce", "xn--4gbrim",
        "xn--54b7fta0cc", "xn--55qw42g", "xn--55qx5d", "xn--5tzm5g",
        "xn--6frz82g", "xn--80adxhks", "xn--80ao21a", "xn--80aqecdr1a",
        "xn--80asehdb", "xn--80aswg", "xn--90a3ac", "xn--90ae",
        "xn--90ais", "xn--c1avg", "xn--d1acj3b", "xn--fiqs8s",
        "xn--fiqz9s", "xn--j1aef", "xn--j1amh", "xn--mgbaam7a8h",
        "xn--mgbayh7gpa", "xn--mgbbh1a", "xn--mgbbh1a71e", "xn--p1acf",
        "xn--p1ai", "xn--qcka1pmc", "xn--wgbh1c", "xn--y9a3aq",
        "xn--ygbi2ammx",
    ],
}


def normalize_tld(tld: str) -> str:
    return tld.strip().lower().lstrip(".")


def unique_preserve_order(items: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        item = normalize_tld(item)
        if item and item not in seen:
            out.append(item)
            seen.add(item)
    return out


def group_names() -> list[str]:
    return [name for name, values in TLD_GROUPS.items() if isinstance(values, list)]


def get_group(name: str) -> list[str]:
    try:
        value = TLD_GROUPS[name]
    except KeyError as exc:
        available = ", ".join(group_names())
        raise KeyError(f"Groupe TLD inconnu: {name}. Groupes disponibles: {available}") from exc
    if not isinstance(value, list):
        raise ValueError(f"{name!r} n'est pas un groupe de TLDs.")
    return list(value)


def combine_groups(*names: str) -> list[str]:
    merged: list[str] = []
    for name in names:
        merged.extend(get_group(name))
    return unique_preserve_order(merged)


def group_counts() -> list[tuple[str, int]]:
    return [(name, len(get_group(name))) for name in group_names()]

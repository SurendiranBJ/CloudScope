# AWS region code → friendly city/location name mapping.
# IMPORTANT: Keep this list in sync with the frontend mirror at:
#   frontend/src/utils/regionNames.ts
# When adding new regions here, add them there too (and vice-versa).

REGION_FRIENDLY_NAMES: dict[str, str] = {
    # Asia Pacific
    "ap-south-1":     "Mumbai",
    "ap-south-2":     "Hyderabad",
    "ap-southeast-1": "Singapore",
    "ap-southeast-2": "Sydney",
    "ap-southeast-3": "Jakarta",
    "ap-southeast-4": "Melbourne",
    "ap-northeast-1": "Tokyo",
    "ap-northeast-2": "Seoul",
    "ap-northeast-3": "Osaka",
    "ap-east-1":      "Hong Kong",
    # US
    "us-east-1":      "N. Virginia",
    "us-east-2":      "Ohio",
    "us-west-1":      "N. California",
    "us-west-2":      "Oregon",
    # Canada
    "ca-central-1":   "Canada Central",
    "ca-west-1":      "Calgary",
    # Europe
    "eu-west-1":      "Ireland",
    "eu-west-2":      "London",
    "eu-west-3":      "Paris",
    "eu-central-1":   "Frankfurt",
    "eu-central-2":   "Zurich",
    "eu-north-1":     "Stockholm",
    "eu-south-1":     "Milan",
    "eu-south-2":     "Spain",
    # Middle East & Africa
    "me-south-1":     "Bahrain",
    "me-central-1":   "UAE",
    "af-south-1":     "Cape Town",
    # South America
    "sa-east-1":      "Sao Paulo",
    # GovCloud (US)
    "us-gov-east-1":  "GovCloud US-East",
    "us-gov-west-1":  "GovCloud US-West",
}


def get_friendly_name(region_code: str) -> str:
    """Return the friendly display name for a region code, or the raw code if unmapped."""
    return REGION_FRIENDLY_NAMES.get(region_code, region_code)

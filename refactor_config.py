import os
import glob
import re

def replace_in_file(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    original_content = content

    # Standard replacements
    content = re.sub(r'os\.getenv\("ENVIRONMENT",\s*"development"\)\.lower\(\)\s*==\s*"production"', 'settings.is_production', content)
    content = re.sub(r'os\.getenv\("ENVIRONMENT",\s*""\)\.lower\(\)\s*==\s*"production"', 'settings.is_production', content)
    content = re.sub(r'os\.getenv\("ENVIRONMENT"\)\.lower\(\)\s*==\s*"production"', 'settings.is_production', content)
    content = re.sub(r'os\.getenv\("DEV_AUTH_MODE",\s*"false"\)\.lower\(\)\s*==\s*"true"', 'settings.DEV_AUTH_MODE', content)
    content = re.sub(r'os\.getenv\("DEV_AUTH_MODE",\s*"false"\)\.lower\(\)\s*in\s*\("true",\s*"1",\s*"yes"\)', 'settings.DEV_AUTH_MODE', content)
    content = re.sub(r'os\.getenv\("AUTH_ENABLED",\s*"false"\)\.lower\(\)\s*in\s*\("true",\s*"1",\s*"yes"\)', 'settings.AUTH_ENABLED', content)
    content = re.sub(r'os\.getenv\("AUTH_REQUIRED",\s*"false"\)\.lower\(\)\s*in\s*\("true",\s*"1",\s*"yes"\)', 'settings.AUTH_REQUIRED', content)
    
    # Specific variables
    content = re.sub(r'os\.getenv\("DATABASE_URL",\s*f"sqlite:///{DEFAULT_DB_FILE}"\)', 'settings.DATABASE_URL', content)
    content = re.sub(r'int\(os\.getenv\("DB_POOL_SIZE",\s*"10"\)\)', 'settings.DB_POOL_SIZE if hasattr(settings, "DB_POOL_SIZE") else 10', content)
    content = re.sub(r'int\(os\.getenv\("DB_MAX_OVERFLOW",\s*"20"\)\)', 'settings.DB_MAX_OVERFLOW if hasattr(settings, "DB_MAX_OVERFLOW") else 20', content)
    content = re.sub(r'int\(os\.getenv\("DB_POOL_TIMEOUT",\s*"30"\)\)', 'settings.DB_POOL_TIMEOUT if hasattr(settings, "DB_POOL_TIMEOUT") else 30', content)

    content = re.sub(r'int\(os\.getenv\("SNAPSHOT_RETENTION_COUNT",\s*"10"\)\)', 'settings.SNAPSHOT_RETENTION_COUNT', content)
    content = re.sub(r'int\(os\.getenv\("AUDIT_RETENTION_DAYS",\s*"90"\)\)', 'settings.AUDIT_RETENTION_DAYS', content)
    
    content = re.sub(r'os\.getenv\("APP_VERSION",\s*"1\.0\.0"\)', 'settings.APP_VERSION', content)
    content = re.sub(r'os\.getenv\("BUILD_VERSION",\s*f"v\{APP_VERSION\}"\)', '(settings.BUILD_VERSION or f"v{settings.APP_VERSION}")', content)
    content = re.sub(r'os\.getenv\("GIT_COMMIT",\s*os\.getenv\("COMMIT_SHA",\s*os\.getenv\("APP_VERSION",\s*os\.getenv\("IMAGE_TAG",\s*"unknown"\)\)\)\)', '(settings.GIT_COMMIT or settings.COMMIT_SHA or settings.APP_VERSION or settings.IMAGE_TAG or "unknown")', content)

    content = re.sub(r'os\.getenv\("OIDC_ISSUER_URL",\s*""\)\.rstrip\("/"\)', 'settings.OIDC_ISSUER_URL.rstrip("/")', content)
    content = re.sub(r'os\.getenv\("OIDC_ISSUER_URL",\s*""\)\.strip\(\)', 'settings.OIDC_ISSUER_URL.strip()', content)
    content = re.sub(r'os\.getenv\("OIDC_ISSUER_URL"\)', 'settings.OIDC_ISSUER_URL', content)

    content = re.sub(r'os\.getenv\("OIDC_AUDIENCE",\s*""\)\.strip\(\)', 'settings.OIDC_AUDIENCE.strip()', content)
    content = re.sub(r'os\.getenv\("OIDC_AUDIENCE",\s*""\)', 'settings.OIDC_AUDIENCE', content)
    content = re.sub(r'os\.getenv\("OIDC_AUDIENCE"\)', 'settings.OIDC_AUDIENCE', content)
    
    content = re.sub(r'os\.getenv\("OIDC_JWKS_URL",\s*""\)\.strip\(\)', 'settings.OIDC_JWKS_URL.strip()', content)
    content = re.sub(r'os\.getenv\("OIDC_JWKS_URL",\s*""\)', 'settings.OIDC_JWKS_URL', content)

    content = re.sub(r'os\.getenv\("JWT_SECRET",\s*""\)\.strip\(\)', 'settings.JWT_SECRET.strip()', content)
    content = re.sub(r'os\.getenv\("JWT_SECRET",\s*""\)', 'settings.JWT_SECRET', content)
    content = re.sub(r'os\.getenv\("JWT_SECRET"\)', 'settings.JWT_SECRET', content)

    content = re.sub(r'os\.getenv\("JWT_ALGORITHM",\s*"HS256"\)', 'settings.JWT_ALGORITHM', content)
    content = re.sub(r'os\.getenv\("JWT_ALGORITHM"\)', 'settings.JWT_ALGORITHM', content)
    
    content = re.sub(r'os\.getenv\("NEO4J_PASSWORD",\s*""\)\.strip\(\)', 'settings.NEO4J_PASSWORD.strip()', content)
    
    content = re.sub(r'os\.getenv\("AUTH_ENABLED",\s*"false"\)\.lower\(\)', 'str(settings.AUTH_ENABLED).lower()', content)
    content = re.sub(r'os\.getenv\("AUTH_REQUIRED",\s*"false"\)\.lower\(\)', 'str(settings.AUTH_REQUIRED).lower()', content)
    content = re.sub(r'os\.getenv\("DEV_AUTH_MODE",\s*"false"\)\.lower\(\)', 'str(settings.DEV_AUTH_MODE).lower()', content)

    content = re.sub(r'int\(os\.getenv\("RATE_LIMIT_SCAN_MAX",\s*"5"\)\)', 'settings.RATE_LIMIT_SCAN_MAX', content)
    content = re.sub(r'int\(os\.getenv\("RATE_LIMIT_SCAN_WINDOW",\s*"600"\)\)', 'settings.RATE_LIMIT_SCAN_WINDOW', content)
    content = re.sub(r'int\(os\.getenv\("RATE_LIMIT_COPILOT_MAX",\s*"30"\)\)', 'settings.RATE_LIMIT_COPILOT_MAX', content)
    content = re.sub(r'int\(os\.getenv\("RATE_LIMIT_COPILOT_WINDOW",\s*"60"\)\)', 'settings.RATE_LIMIT_COPILOT_WINDOW', content)
    content = re.sub(r'int\(os\.getenv\("RATE_LIMIT_SIMULATION_MAX",\s*"30"\)\)', 'settings.RATE_LIMIT_SIMULATION_MAX', content)
    content = re.sub(r'int\(os\.getenv\("RATE_LIMIT_SIMULATION_WINDOW",\s*"60"\)\)', 'settings.RATE_LIMIT_SIMULATION_WINDOW', content)
    content = re.sub(r'int\(os\.getenv\("RATE_LIMIT_FINDING_MAX",\s*"60"\)\)', 'settings.RATE_LIMIT_FINDING_MAX', content)
    content = re.sub(r'int\(os\.getenv\("RATE_LIMIT_FINDING_WINDOW",\s*"60"\)\)', 'settings.RATE_LIMIT_FINDING_WINDOW', content)
    content = re.sub(r'int\(os\.getenv\("RATE_LIMIT_AUDIT_MAX",\s*"60"\)\)', 'settings.RATE_LIMIT_AUDIT_MAX', content)
    content = re.sub(r'int\(os\.getenv\("RATE_LIMIT_AUDIT_WINDOW",\s*"60"\)\)', 'settings.RATE_LIMIT_AUDIT_WINDOW', content)
    content = re.sub(r'int\(os\.getenv\("RATE_LIMIT_EXPORT_MAX",\s*"20"\)\)', 'settings.RATE_LIMIT_EXPORT_MAX', content)
    content = re.sub(r'int\(os\.getenv\("RATE_LIMIT_EXPORT_WINDOW",\s*"60"\)\)', 'settings.RATE_LIMIT_EXPORT_WINDOW', content)
    content = re.sub(r'int\(os\.getenv\("RATE_LIMIT_GENERAL_MAX",\s*"300"\)\)', 'settings.RATE_LIMIT_GENERAL_MAX', content)
    content = re.sub(r'int\(os\.getenv\("RATE_LIMIT_GENERAL_WINDOW",\s*"60"\)\)', 'settings.RATE_LIMIT_GENERAL_WINDOW', content)
    
    content = re.sub(r'int\(os\.getenv\("SCAN_LOCK_LEASE_SECONDS",\s*"180"\)\)', 'settings.SCAN_LOCK_LEASE_SECONDS', content)

    content = re.sub(r'os\.getenv\("LOG_FORMAT",\s*"json"\)\.lower\(\)', 'settings.LOG_FORMAT.lower()', content)
    content = re.sub(r'os\.getenv\("LOG_LEVEL",\s*"INFO"\)\.upper\(\)', 'settings.LOG_LEVEL.upper()', content)

    if content != original_content:
        # Add import if needed
        if 'from app.config import settings' not in content:
            # Try to add it after imports
            content = "from app.config import settings\n" + content
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"Updated {filepath}")

for f in glob.glob('backend/app/**/*.py', recursive=True):
    replace_in_file(f)

#!/usr/bin/env python3
import secrets
import string

def generate_secret(length=32):
    return secrets.token_hex(length)

def generate_password(length=16):
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for i in range(length))

if __name__ == "__main__":
    print("=" * 60)
    print("  CloudScope Auto-Generated Secrets")
    print("=" * 60)
    print(f"JWT_SECRET={generate_secret(32)}")
    print(f"NEO4J_PASSWORD={generate_password(24)}")
    print("=" * 60)
    print("Copy these values into your .env file.")

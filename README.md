## SignedJwt-PrivEsc
---

This tool specifically targets the `iam.serviceAccounts.signJwt` permission to generate an Access Token for a target Service Account without needing its private key.

### OverView
---

In GCP, if an identity has the Service Account Token Creator role (or specifically iam.serviceAccounts.signJwt), they can sign a well-formed JWT which can be used to request Access Token for service Accounts. This script works as follows:

   - Constructs an unsigned JWT with the target ServiceAccount as the issuer
   - Calls the `signJwt` method of the IAM API, and passes the constructed JWT as the payload
   - Exchanges the signed JWT for a full OAuth2 Access Token.


### Options
---

```shell
usage: signedjwt-privesc.py [-h] (-t TOKEN | -f TOKEN_FILE | -k KEY_FILE) -s TARGET

Own Accounts with signJwt

options:
  -h, --help            show this help message and exit
  -t, --token TOKEN     Caller's Access Token string
  -f, --token-file TOKEN_FILE
                        Path to file containing Access Token
  -k, --key-file KEY_FILE
                        Path to Service Account JSON key file
  -s, --target-account TARGET   Target Service Account Email
```


### Prerequisites
---
    - Python 3.x
    - The iamcredentials.googleapis.com API must be enabled in the target project.
    - Your caller identity must have iam.serviceAccounts.signJwt permission on the target account.


### Installation
---

```
git clone https://github.com/5epi0l/signedJwt-PrivEsc.git
cd signedJwt-PrivEsc
pip install -r requirements.txt
```

### Usage
---

1. Using a direct Access Token

```shell
python3 signedjwt-privesc.py -t $(gcloud auth print-access-token) -s target-sa@project-id.iam.gserviceaccount.com
```

2. Using a Service Account JSON Key

```shell
python3 signedjwt-privesc.py -k /path/to/key.json -s target-sa@project-id.iam.gserviceaccount.com
```

3. Using a Token File

```shell
python3 signedjwt-privesc.py -f ./token.txt -s target-sa@project-id.iam.gserviceaccount.com
```


## Disclaimer
---

This tool is for authorized security auditing and educational purposes only. Unauthorized access to computer systems is illegal.


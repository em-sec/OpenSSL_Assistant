# OpenSSL_Assistant
This is a tool meant to simplify the administration of an OpenSSL Intermediate Certificate Authority.

**Pre-requisites:**
- Python 3 (tested on 3.6+)
- Knowledge of administering an OpenSSL certificate authority

**Important:**
This program is written with a few assumptions.
   1. That you are running it from an intermediate certificate authority - not the root.
   2. The certificate authority is running on a RHEL-based Linux system (tested on CentOS 7)
      a. Should work on Debian-based systems as well
   3. Your intermediate certificate authority is structured as described in https://jamielinux.com/docs/openssl-certificate-authority/index.html
      a. The only exception is to use the openssl.cnf file from this repo instead of the one in Jamie's guide (I added a few things to make it suitable for enterprise deployments)
      b. Your directory structure MUST be the same

**Instructions:**
- Modify any of the paths at the beginning of the script to match your values
- Modify the following in openssl.cnf
   - Default values (lines 82-86)
   - CRL distribution points (lines 113, 125)
- Copy the script onto your Intermediate Certificate Authority
- Run the script as root

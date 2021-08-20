#!/usr/bin/python3

# Version: 1.0
# Created by: eric@em-sec.com

import os, re

# Edit these paths if needed
# -------------------------------------------------------------------------------------------------------------------------------------
crl_file = '/root/ca/intermediate/crl/intermediate.crl.pem' # Path to your CRL - this will be overwritten                              
int_conf = '/root/ca/intermediate/openssl.cnf' # Path to the openssl.cnf from the repo
ca_cert = '/root/ca/certs/ca.cert.pem' # Path to the root CA (this is just a copy for you to reference if needed)
int_cert = '/root/ca/intermediate/certs/intermediate.cert.pem' # Path to the intermediate CA cert
cert_chain = '/root/ca/intermediate/certs/ca-chain.cert.pem' # Path to the certificate chain (root and intermediate in single file)
# -------------------------------------------------------------------------------------------------------------------------------------

# Makes sure the script is being run as root
if os.geteuid() != 0:
    print('[ERROR] This script must be run as root')
    print('')
    exit()

# The main menu
rootmenu = """
Welcome to the EM-Sec OpenSSL certificate authority tool.

Selection from the options below:
---------------------------------
1. Create a certificate
2. Print the Root certificate
3. Print the Intermediate certificate
4. Print the certificate chain
5. Revoke a certificate
6. Create the CRL"""

menu1 = """
You have selected to create a certificate.

Selection from the options below:
---------------------------------
1. I need to create a key and certificate
2. I already have a CSR"""

menu1a = """
Creating a certificate/key pair:
--------------------------------"""

menu2 = """
You have selected to print the root certificate.

Copy everything below this line:
--------------------------------
"""

menu3 = """
You have selected to print the intermediate root certificate.

Copy everything below this line:
--------------------------------
"""

menu4 = """
You have selected to print the certificate chain.

Copy everything below this line:
--------------------------------
"""

menu5 = """
You have selected to revoke a certificate."""

menu6 = """
You have selected to create the CRL."""

errormsg = """
Sorry - it appears you've selected an invalid option."""

# This function determines if the value provided is an interger and returns true
def is_int(test):
    try:
        if int(test):
            return True
    except:
        return False

# This function determined if the user entered an appropriate answer to the [y/n] prompt
def yes_no(msg):
    answer = input('{0} [y/n]: '.format(msg)).lower()
    answer = answer.strip()
    yes = ['y', 'yes']
    if answer in yes:
        return True
    else:
        return False

# This function receives input to selection options and cleans it up, then converts it to an integer
def get_selection():
    selection = input('Select: ')
    selection = selection.strip()
    while is_int(selection) != True:
        display_error(selection)
        selection = input('Select: ')
        is_int(selection)
    return int(selection)

# This function displays an error message
def display_error(selection):
    print(errormsg)
    print('Your selection: {0}'.format(selection))
    print('')

# This function exits the program if it receives a False value
def exit_if_false(test):
    if test:
        pass
    else:
        exit()

# This function creates the CRL and writes it to the crl_file value
def generate_crl():
    os.system('openssl ca -config {0} -gencrl -out {1}'.format(int_conf, crl_file))
    print('CRL successfully created at: {0}'.format(crl_file))

# This function revokes the certificate and then creates an updated CRL
def revoke_cert():
    fqdn = input('Enter the server FQDN of the certificate to revoke: ').lower()
    fqdn = fqdn.strip()
    seg_count = 0
    seg_count = len(fqdn.split('.'))
    while seg_count < 3:
        print('')
        print('You did not enter a valid FQDN. Try again.')
        fqdn = input('Enter the server FQDN: ').lower()
        fqdn = fqdn.strip()
        seg_count = len(fqdn.split('.'))
    rev_cert = '/root/ca/intermediate/certs/{0}.cert.pem'.format(fqdn)
    try:
        os.system('openssl ca -config {0} -revoke {1}'.format(int_conf, rev_cert))
        print('Successfully revoked: {0}'.format(rev_cert))
    except:
        print('Unable to revoke certificate - please do so manually')
        exit()

# Start of the program
print(rootmenu)
rootmenu_selection = get_selection()
# Option 1 - Create a certificate
if rootmenu_selection == 1:
    print(menu1)
    menu1_selection = get_selection()
    # Option 1.1 - Create a private key, csr, and certificate
    if menu1_selection == 1:
        print(menu1a)
        seg_count = 0
        fqdn = input('Enter the server FQDN: ').lower()
        fqdn = fqdn.strip()
        hostname = fqdn.split('.')[0]
        seg_count = len(fqdn.split('.'))
        while seg_count < 3:
            print('')
            print('You did not enter a valid FQDN. Try again.')
            fqdn = input('Enter the server FQDN: ').lower()
            fqdn = fqdn.strip()
            hostname = fqdn.split('.')[0]
            seg_count = len(fqdn.split('.'))
        ip_addrs = input('Enter the server IP addresses, separated by commas: ').split(',')
        ip_reg = re.compile('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
        dns_list = [fqdn, hostname]
        ip_list = []
        for ip in ip_addrs:
            ip = ip.strip()
            if ip_reg.match(ip):
                dns_list.append(ip)
                ip_list.append(ip)
                pass
            else:
                print('{0} is not a valid ip address. It has not been added.'.format(ip))
        if yes_no('Do you want to add any aliases? '):
            aliases = input('Enter aliases, separated by commas: ').split(',')
            for alias in aliases:
                alias = alias.strip()
                dns_list.append(alias)
        ukey_present = 0
        new_key = '/root/ca/intermediate/private/{0}.key.pem'.format(fqdn)
        new_ukey = '/root/ca/intermediate/private/{0}.ukey.pem'.format(fqdn)
        new_csr = '/root/ca/intermediate/csr/{0}.csr.pem'.format(fqdn)
        new_cert = '/root/ca/intermediate/certs/{0}.cert.pem'.format(fqdn)
        new_cnf_file = '/root/ca/intermediate/openssl-{0}.cnf'.format(hostname)
        new_config = []
        with open(int_conf, 'r') as old_conf:
            conf_lines = old_conf.readlines()
            line_count = 0
            stop = 0
            dns_count = 0
            ip_count = 0
            for line in conf_lines:
                if stop != 1:
                    line_count += 1
                    if line == '[ alt_names ]\n':
                        print('Found title')
                        stop += 1
                    new_config.append(line)
                    if line.startswith('organizationalUnitName_default'):
                        new_config.append('commonName_default           = {0}\n'.format(fqdn))
            for host in dns_list:
                dns_count += 1
                new_config.append('DNS.{0} = {1}\n'.format(dns_count, host))
            for ip in ip_list:
                ip_count += 1
                new_config.append('IP.{0} = {1}\n'.format(ip_count, ip))
        with open(new_cnf_file, 'w') as new_cnf:
            new_cnf.writelines(new_config)
        print('')
        print('-------------------------')
        print('Creating the private key:')
        print('-------------------------')
        os.system('openssl genrsa -aes256 -out {0} 2048'.format(new_key))
        os.system('chmod 400 {0}'.format(new_key))
        print('')
        print('-----------------')
        print('Creating the csr:')
        print('-----------------')
        os.system('openssl req -config {0} -key {1} -new -sha256 -out {2}'.format(new_cnf_file, new_key, new_csr))
        print('')
        print('---------------------------')
        print('Generating the certificate:')
        print('---------------------------')
        os.system('openssl ca -config {0} -extensions server_cert -notext -in {1} -out {2}'.format(new_cnf_file, new_csr, new_cert))
        os.system('chmod 444 {0}'.format(new_cert))
        print('')
        if yes_no('Do you want to create an unencrypted key?'):
            ukey_present += 1
            print('-------------------------')
            print('Generating plaintext key:')
            print('-------------------------')
            os.system('openssl rsa -in {0} -out {1}'.format(new_key, new_ukey))
            os.system('chmod 400 {0}'.format(new_ukey))
        print('')
        print('-----------------------------------------------------------')
        print('Certificate successfully generated. Please verify it below:')
        print('-----------------------------------------------------------')
        os.system('sleep 5')
        os.system('openssl x509 -noout -text -in {0}'.format(new_cert))
        print('')
        if yes_no('Does everything look okay?') == False:
            print('')
            print('Something must have gone wrong. Please retry the certificate generation.')
            exit()
        print('')
        if yes_no('Do you want to print the files out to screen?'):
            print('')
            print('----------------------')
            print('Encrypted private key:')
            print('----------------------')
            print('')
            os.system('cat {0}'.format(new_key))
            print('')
            if ukey_present > 0:
                print('----------------------')
                print('Decrypted private key:')
                print('----------------------')
                print('')
                os.system('cat {0}'.format(new_ukey))
                print('')
            print('------------')
            print('Certificate:')
            print('------------')
            print('')
            os.system('cat {0}'.format(new_cert))
            print('')
    # Option 1.2 - Create a certificate from a provided csr
    elif menu1_selection == 2:
        print('Expected location: /root/ca/intermediate/csr/<fqdn>.csr.pem')
        menu1_option2 = yes_no('Have you already put the CSR into the appropriate place?')
        exit_if_false(menu1_option2)
        seg_count = 0
        fqdn = input('Enter the server FQDN: ').lower()
        fqdn = fqdn.strip()
        hostname = fqdn.split('.')[0]
        seg_count = len(fqdn.split('.'))
        while seg_count < 3:
            print('')
            print('You did not enter a valid FQDN. Try again.')
            fqdn = input('Enter the server FQDN: ').lower()
            fqdn = fqdn.strip()
            hostname = fqdn.split('.')[0]
            seg_count = len(fqdn.split('.'))
        ip_addrs = input('Enter the server IP addresses, separated by commas: ').split(',')
        ip_reg = re.compile('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
        dns_list = [fqdn, hostname]
        ip_list = []
        for ip in ip_addrs:
            ip = ip.strip()
            if ip_reg.match(ip):
                dns_list.append(ip)
                ip_list.append(ip)
                pass
            else:
                print('{0} is not a valid ip address. It has not been added.'.format(ip))
        if yes_no('Do you want to add any aliases? '):
            aliases = input('Enter aliases, separated by commas: ').split(',')
            for alias in aliases:
                alias = alias.strip()
                dns_list.append(alias)
        new_csr = '/root/ca/intermediate/csr/{0}.csr.pem'.format(fqdn)
        new_cert = '/root/ca/intermediate/certs/{0}.cert.pem'.format(fqdn)
        new_cnf_file = '/root/ca/intermediate/openssl-{0}.cnf'.format(hostname)
        new_config = []
        with open(int_conf, 'r') as old_conf:
            conf_lines = old_conf.readlines()
            line_count = 0
            stop = 0
            dns_count = 0
            ip_count = 0
            for line in conf_lines:
                if stop != 1:
                    line_count += 1
                    if line == '[ alt_names ]\n':
                        stop += 1
                    new_config.append(line)
                    if line.startswith('organizationalUnitName_default'):
                        new_config.append('commonName_default           = {0}\n'.format(fqdn))
            for host in dns_list:
                dns_count += 1
                new_config.append('DNS.{0} = {1}\n'.format(dns_count, host))
            for ip in ip_list:
                ip_count += 1
                new_config.append('IP.{0} = {1}\n'.format(ip_count, ip))
        with open(new_cnf_file, 'w') as new_cnf:
            new_cnf.writelines(new_config)
        print('---------------------------')
        print('Generating the certificate:')
        print('---------------------------')
        os.system('openssl ca -config {0} -extensions server_cert -notext -in {1} -out {2}'.format(new_cnf_file, new_csr, new_cert))
        os.system('chmod 444 {0}'.format(new_cert))
        print('')
        print('-----------------------------------------------------------')
        print('Certificate successfully generated. Please verify it below:')
        print('-----------------------------------------------------------')
        os.system('sleep 5')
        os.system('openssl x509 -noout -text -in {0}'.format(new_cert))
        print('')
        if yes_no('Does everything look okay?') == False:
            print('Something must have gone wrong. Please retry the certificate generation.')
            print('')
            exit()
        print('')
        if yes_no('Do you want to print the files out to screen?'):
            print('')
            print('------------')
            print('Certificate:')
            print('------------')
            print('')
            os.system('cat {0}'.format(new_cert))
            print('')
    else:
        display_error(rootmenu_selection)
# Option 2 - Print the root cert to screen
elif rootmenu_selection == 2:
    print(menu2)
    os.system('cat {0}'.format(ca_cert))
    print('')
# Option 3 - Print the intermediate cert to screen
elif rootmenu_selection == 3:
    print(menu3)
    os.system('cat {0}'.format(int_cert))
    print('')
# Option 4 - Print the certificate chain to screen
elif rootmenu_selection == 4:
    print(menu4)
    os.system('cat {0}'.format(cert_chain))
    print('')
# Option 5 - Revoke a certificate
elif rootmenu_selection == 5:
    print(menu5)
    revoke_cert()
    generate_crl()
# Option 6 - Create a CRL
elif rootmenu_selection == 6:
    print(menu6)
    generate_crl()
# If an invalid integer is entered
else:
    display_error(rootmenu_selection)
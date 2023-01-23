#!/usr/bin/env python2.7
#
# nanitor-server-ctl - Install and manage the Nanitor server.

from datetime import datetime
import base64
import argparse
import getpass
import hashlib
import platform
import re
import json
import os
import random
import shutil
import signal
import string
from subprocess import Popen, call, check_output, CalledProcessError
import socket
import sys
import time
import urllib2
from urlparse import urlparse
from uuid import uuid4
import ConfigParser

# Configs get written here.
CONFIG_WRITE_DIR = "/etc/nanitor"

NANITOR_CLI_SETTINGS = "/etc/nanitor/nanitor_cli.ini"
NANITOR_MANAGER_SETTINGS = "/etc/nanitor/nanitor_manager.ini"

NGINX_CONFIG_DIR = "/etc/nginx/conf.d"

LD_LIBRARY_PATH = "/usr/lib/nanitor-server/lib/openscap"

LOG_FILE = "/tmp/nanitor_installer.log"

# When doing a clean OEM install, install specifics will be written here.
NANITOR_SERVER_INSTALL_OUT = "/root/nanitor_server_install.out"

NANITOR_LIB = "/var/lib/nanitor"
NANITOR_LIB_SERVER = os.path.join(NANITOR_LIB, "server")

OPENSSL_KEYS_DIR = os.path.join(NANITOR_LIB_SERVER, "keys")
OPENSSL_PRIVATE_KEY = os.path.join(OPENSSL_KEYS_DIR, "private.pem")
OPENSSL_PUBLIC_KEY = os.path.join(OPENSSL_KEYS_DIR, "public.pem")

# Certficate dir to store SSL certificates for NGINX.
SSL_CERTS_DIR = "/etc/ssl/local"
SSL_KEY_PATH = os.path.join(SSL_CERTS_DIR, "nanitor.key")
SSL_FULLCERT_PATH = os.path.join(SSL_CERTS_DIR, "nanitor.crt")

# This is the Nanitor DATA certs dir where certificates are copied to.
NANITOR_CERTIFICATES_DIR = os.path.join(NANITOR_LIB_SERVER, "certificates")
NANITOR_CSR_PATH = os.path.join(NANITOR_CERTIFICATES_DIR, "server.csr")
NANITOR_FULLCERT_PATH = os.path.join(NANITOR_CERTIFICATES_DIR, "server.nginx.crt")

UPGRADE_COMPONENTS = ["ui", "server"]

CENTOS_SERVER_REPO_STABLE_PATH = "/etc/yum.repos.d/nanitor-server-centos-stable.repo"
CENTOS_SERVER_REPO_TESTING_PATH = "/etc/yum.repos.d/nanitor-server-centos-testing.repo"

SERVICES = ["nanitor-nsq", "nanitor-api", "nanitor-manager", "nanitor-ui-api", "nanitor-system-api", "nanitor-ui-runner", "nanitor-collector-socket"]

NANITOR_ETC = "/etc/nanitor"
NANITOR_COMMON_INI = "/etc/nanitor/nanitor_common.ini"

URL_COLLECTOR_RPM = "hub.nanitor.com/files/yum/nanitor-collector.rpm"
URL_SERVER_RPM = "hub.nanitor.com/files/yum/nanitor-server.rpm"

IFCFG_NETWORK_PATH = "/etc/sysconfig/network-scripts/ifcfg-eth0"
IFCFG_NETWORK_TEMPLATE = """DEVICE="eth0"
BOOTPROTO="static"
ONBOOT="yes"
IPV6INIT="yes"
IPV6_AUTOCONF="yes"
NM_CONTROLLED="no"
PEERDNS="no"
GATEWAY="{gateway}"
IPADDR0="{address}"
PREFIX0="{prefix}"
"""

CENTOS_BASE_REPO_FILE = """[base]
name=CentOS-$releasever - Base
baseurl=https://hub.nanitor.com/centos/7/os/x86_64/
gpgcheck=1
exclude=postgresql*

[updates]
name=CentOS-$releasever - Updates
baseurl=https://hub.nanitor.com/centos/7/updates/x86_64/
gpgcheck=1
exclude=postgresql*

[postgresql13]
name=CentOS-$releasever - Updates
baseurl=https://hub.nanitor.com/centos/7/postgresql-13/x86_64/
gpgcheck=1
"""

# We look for this marker to identify whether system_api is in nginx already.
NGINX_SYSTEM_API_SECTION_IDENTIFIER = "location /system_api/"

# We will insert this into nginx config if it does not exist.
NGINX_SYSTEM_API_SECTION = """    location /system_api/ {
        proxy_redirect off;
        proxy_set_header   Host             $host;
        proxy_set_header   X-Real-IP        $remote_addr;
        proxy_set_header   X-Forwarded-For  $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-Ssl on;
        proxy_pass http://127.0.0.1:8169/;
    }
"""

# We look for this marker to identify whether collector_socket is in nginx already.
NGINX_COLLECTOR_SOCKET_SECTION_IDENTIFIER = "location /collector_socket/"

# We will insert this into nginx config if it does not exist.
NGINX_COLLECTOR_SOCKET_SECTION = """    location /collector_socket/ {
        proxy_redirect off;
        proxy_set_header   Host             $host;
        proxy_set_header   X-Real-IP        $remote_addr;
        proxy_set_header   X-Forwarded-For  $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-Ssl on;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_pass http://127.0.0.1:8164/;
    }
"""

RESOLVCONF_PATH = "/etc/resolv.conf"
ENVIRONMENT_PATH = "/etc/environment"
HOSTNAME_PATH = "/etc/hostname"

# For testing, allow settings this environment variable to re-use SERVER_INSTALLATION_ID.
TEST_SERVER_INSTALLATION_ID_VARIABLE = "NANTOR_SERVER_INSTALLATION_ID"


def get_server_rpm_url(use_http=False):
    prefix = "http" if use_http else "https"
    return "{prefix}://hub.nanitor.com/files/yum/nanitor-server.rpm".format(prefix=prefix)


def get_ui_rpm_url(use_http=False):
    prefix = "http" if use_http else "https"
    return "{prefix}://hub.nanitor.com/files/yum/nanitor-ui.rpm".format(prefix=prefix)


def _get_hostname():
    if not os.path.isfile(HOSTNAME_PATH):
        return platform.uname()[1]

    return open(HOSTNAME_PATH, "rb").read().strip()


def env_string_from_dict(env_dict):
    return ' '.join(['{0}="{1}"'.format(key, value) for (key, value) in env_dict.items()])


def get_cli_env_string():
    env_dict = {}
    env_dict['NANITOR_CLI_SETTINGS'] = NANITOR_CLI_SETTINGS
    env_dict['LD_LIBRARY_PATH'] = LD_LIBRARY_PATH
    env_dict['NANITOR_TEST_CLI'] = "true"
    env_dict['NANITOR_DEV_CLI'] = "true"

    add_proxy_variables(env_dict)
    return env_string_from_dict(env_dict)


def get_manager_env_string():
    env_dict = {}
    env_dict['NANITOR_MANAGER_SETTINGS'] = NANITOR_MANAGER_SETTINGS
    env_dict['LD_LIBRARY_PATH'] = LD_LIBRARY_PATH
    env_dict['NANITOR_TEST_CLI'] = "true"
    env_dict['NANITOR_DEV_CLI'] = "true"

    add_proxy_variables(env_dict)
    return env_string_from_dict(env_dict)


def random_string(length=12):
    return ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for i in range(length))


def get_envvar_case(env_var):
    ret = os.getenv(env_var)
    if ret:
        return ret

    return os.getenv(env_var.lower())


def get_envvar_case_str_true(env_var):
    str_status = get_envvar_case(env_var)
    if not str_status:
        return False

    return str_status.lower() in ["true", "yes"]


# Add proxy variables to an incoming env cmd dictionary.
def add_proxy_variables(env_dict):
    http_proxy = get_envvar_case('http_proxy')
    if http_proxy:
        env_dict['http_proxy'] = http_proxy

    https_proxy = get_envvar_case('https_proxy')
    if https_proxy:
        env_dict['https_proxy'] = https_proxy

    no_proxy = get_envvar_case('no_proxy')
    if no_proxy:
        env_dict['no_proxy'] = no_proxy


# Set up the CentOS repositories so it only points to us.
def _set_yum_repositories(args):
    yum_repos_dir = "/etc/yum.repos.d"
    base_repo_filename = "CentOS-Base.repo"

    for fname in os.listdir(yum_repos_dir):
        fpath = os.path.join(yum_repos_dir, fname)
        if os.path.isdir(fpath):
            continue

        if fname == base_repo_filename:
            with open(fpath, "wb") as fp:
                fp.write(CENTOS_BASE_REPO_FILE)
                fp.write("\n")
        elif fname.startswith("CentOS-"):
            with open(fpath, "wb") as fp:
                fp.write("# Nanitor repo file, please do not delete or change this file.")
                fp.write("\n")
        else:
            os.remove(fpath)


def run_command(cmd, testing=False, needs_root=False, want_output=False, ignore_error=False):
    if not needs_root:
        # Needs to cd /tmp to avoid permission errors from golang martini which
        # does a check to what directory we are executing for and nanitor needs
        # permission to that folder hence choosing /tmp.
        cmd = "cd /tmp && sudo -u nanitor -H " + cmd

    if not want_output:
        cmd += " >{0} 2>&1".format(LOG_FILE)

    if testing:
        print(cmd)
        return

    ret = 0

    if want_output:
        return call(cmd, shell=True)
    else:
        p = Popen(cmd, shell=True)
        p.communicate()
        ret = p.returncode

    if ret != 0:
        log_str = open(LOG_FILE).read()
        sys.stderr.write(log_str + "\n")
        if not ignore_error:
            raise Exception("Failed to run command '{0}'".format(cmd))

    return ret


def get_cli_bin():
    return "/usr/lib/nanitor-server/bin/nanitor-cli"


def get_manager_bin():
    return "/usr/lib/nanitor-server/bin/nanitor-manager"


def _testdb(args):
    cli_bin = get_cli_bin()
    run_command("{env_string} {bin} test_db".format(bin=cli_bin, env_string=get_cli_env_string()), testing=args.testing)


def _test_ldap(args, want_output=True):
    domain = args.domain
    username = args.username

    cli_bin = get_cli_bin()
    run_command("{env_string} {bin} test_ldap --domain '{domain}' --username '{username}'".format(bin=cli_bin, env_string=get_cli_env_string(), domain=domain, username=username), testing=args.testing, want_output=want_output)


def testdb(args):
    _testdb(args)
    print("Database connectivity is ok")


def test_ldap(args, want_output=True):
    _test_ldap(args, want_output)


def _backupdb(dbhost, dbname, dbuser, dbpass, output_file, testing=False):
    """Backup a database to a output file"""
    sslmode = "prefer"
    if dbhost in ['localhost', '127.0.0.1']:
        sslmode = "disable"

    cmd = "PGSSLMODE='{sslmode}' PGPASSWORD='{dbpass}' pg_dump -h {dbhost} -U {dbuser} {dbname} | gzip > {output_file}.gz".format(sslmode=sslmode, dbhost=dbhost, dbname=dbname, dbuser=dbuser, dbpass=dbpass, output_file=output_file)
    # want_output needs to be true as we are compressing on the fly and do not want the output redirected.
    run_command(cmd, testing=testing, want_output=True, needs_root=True)


def _restoredb(dbhost, dbname, dbuser, dbpass, dbdump_path, testing=False):
    """Creates a database with the given credentials and restores it to a DB dump specified"""
    create_user_string = "echo \"CREATE USER {dbuser} WITH NOCREATEDB NOSUPERUSER NOCREATEROLE ENCRYPTED PASSWORD '{dbpass}'\" | sudo -u postgres -H psql".format(dbuser=dbuser, dbpass=dbpass)
    create_db_string = "sudo -u postgres -H createdb -E UTF8 -T template0 --locale=en_US.utf8 -O {dbuser} {dbname}".format(dbname=dbname, dbuser=dbuser)
    create_extension_string = """echo 'CREATE EXTENSION "uuid-ossp"' | sudo -u postgres -H psql {dbuser}""".format(dbuser=dbuser)

    run_command(create_user_string, testing=testing, needs_root=True)
    run_command(create_db_string, testing=testing, needs_root=True)
    run_command(create_extension_string, testing=testing, needs_root=True)

    if dbdump_path:
        sslmode = "prefer"
        if dbhost in ['localhost', '127.0.0.1']:
            sslmode = "disable"

        cmd = "gzip -dc {dbdump_path} | PGSSLMODE='{sslmode}' PGPASSWORD='{dbpass}' psql -h {dbhost} -U {dbuser} {dbname}".format(sslmode=sslmode, dbhost=dbhost, dbname=dbname, dbuser=dbuser, dbpass=dbpass, dbdump_path=dbdump_path)
        run_command(cmd, testing=testing, needs_root=True)


def _initdb(args):
    password = random_string()

    create_user_string = "echo \"CREATE USER nanitor WITH NOCREATEDB NOSUPERUSER NOCREATEROLE ENCRYPTED PASSWORD '{dbpass}'\" | sudo -u postgres -H psql".format(dbpass=password)
    create_db_string = "sudo -u postgres -H createdb -E UTF8 -T template0 --locale=en_US.utf8 -O nanitor nanitor"
    create_extension_string = """echo 'CREATE EXTENSION "uuid-ossp"' | sudo -u postgres -H psql nanitor"""

    run_command(create_user_string, testing=args.testing, needs_root=True)
    run_command(create_db_string, testing=args.testing, needs_root=True)
    run_command(create_extension_string, testing=args.testing, needs_root=True)

    cfg = NANITOR_COMMON_INI
    placeholder = "${DB_PASSWORD}"

    if placeholder not in open(cfg).read():
        raise Exception("Database created, but unable to update nanitor_common.ini because missing placeholder. Password created is: {0}".format(password))

    cmd = "sed -i.bak -e 's/{0}/{1}/g' {2}".format(placeholder, password, cfg)
    run_command(cmd, needs_root=True, testing=args.testing)


# Creates a CSR request ready for a Certification Authority to accept.
# full_hostname is a fully qualified domain name used as a CN and a DNS entry in subjectAltName.
# Argument: nanitor_hostname adds another DNS entry into the subjectAltName.
def _create_csr(args, want_output=True):
    args.full_hostname = _get_hostname()

    if not os.path.isdir(SSL_CERTS_DIR):
        os.makedirs(SSL_CERTS_DIR)

    key_file = SSL_KEY_PATH
    if not os.path.isfile(key_file):
        # Create the SSL key.
        cmd = "openssl genrsa -out {0} 2048".format(key_file)
        run_command(cmd, needs_root=True, testing=args.testing, want_output=want_output)

    hostnames = [args.full_hostname]

    if args.full_hostname != args.nanitor_hostname:
        hostnames.append(args.nanitor_hostname)

    dns_strings = []
    for hostname in hostnames:
        dns_strings.append("DNS:{0}".format(hostname))

    dns_string = ",".join(dns_strings)

    # Now create the CSR request.
    csr_file = os.path.join(SSL_CERTS_DIR, "nanitor.csr")

    # Vendor config, we need to duplicate it and add our stuff to it.
    default_ssl_config = "/etc/pki/tls/openssl.cnf"
    if _is_debian():
        default_ssl_config = "/etc/ssl/openssl.cnf"
    ssl_config = os.path.join(SSL_CERTS_DIR, "openssl.cnf")

    shutil.copy(default_ssl_config, ssl_config)

    with open(ssl_config, "a") as fp:
        fp.write("\n[SAN]\n")
        fp.write("subjectAltName={0}\n".format(dns_string))

    cmd = """
    openssl req -new -sha256 -key {key_file} \
         -subj "/C=IS/ST=RVK/L=REYKJAVIK/O=Nanitor/OU=IT/CN={full_hostname}" \
         -reqexts SAN \
         -config {ssl_config} \
         -out {csr_file}
    """.format(key_file=key_file, full_hostname=args.full_hostname, ssl_config=ssl_config, csr_file=csr_file)

    run_command(cmd, needs_root=True, testing=args.testing, want_output=want_output)

    # Copy to certificates directory.
    shutil.copy(csr_file, NANITOR_CSR_PATH)

    return dict(key_file=key_file, csr_file=csr_file)


def _get_server_url(args):
    use_hostname = args.nanitor_hostname

    url_scheme = "https"
    server_url = "{0}://{1}".format(url_scheme, use_hostname)
    return server_url


def _set_server_url(args, want_output=True):
    cli_bin = get_cli_bin()
    server_url = _get_server_url(args)
    run_command('{env_string} {bin} set-server-url --force {server_url}'
        .format(bin=cli_bin, env_string=get_cli_env_string(), server_url=server_url), testing=args.testing)


def _migratedb(args, want_output=True):
    cli_bin = get_cli_bin()
    run_command("{env_string} {bin} migrate_upgrade head".format(bin=cli_bin, env_string=get_cli_env_string()), testing=args.testing, want_output=want_output)


def _parse_centos_repofile(filepath):
    search_for = "baseurl="
    username = ""
    password = ""
    url_scheme = "https"

    with open(filepath, 'rb') as fp:
        for line in fp:
            line = line.strip()
            if not line.startswith(search_for):
                continue

            # Fishing out username and password from this.
            # baseurl=https://user:pass@packages.nanitor.com/yum/nanitor-server/stable/redhat/rhel-$releasever-$basearch
            idx = line.index(search_for)
            if idx == -1:
                continue

            baseurl = line[idx + len(search_for):]
            bu = urlparse(baseurl)
            username = bu.username
            password = bu.password
            url_scheme = bu.scheme

        return dict(username=username, password=password, url_scheme=url_scheme)


def _hub_sync(args, want_output=True):
    base_url = ""
    username = args.username
    password = args.password
    use_http = args.use_http

    if args.base_url:
        base_url = args.base_url

    cli_bin = get_cli_bin()
    cmd = "{env_string} {bin} customer_portal_sync".format(bin=cli_bin, env_string=get_cli_env_string())

    if username:
        cmd += " --username {username}".format(username=username)

    if password:
        cmd += " --password {password}".format(password=password)

    if base_url:
        cmd += " --base_url {base_url}".format(base_url=base_url)

    if use_http:
        cmd += " --use_http"

    run_command(cmd, testing=args.testing, want_output=want_output)
    return True


def _convert_der_to_pem(der_path, out_path, args, want_output=True):
    cmd = "openssl x509 -inform der -in {0} -out {1}".format(der_path, out_path)
    run_command(cmd, needs_root=True, testing=args.testing, want_output=want_output)


# Process incoming cert and output to a file.
def _cert_process(args, want_output=True):
    args.full_hostname = _get_hostname()

    cert_path = args.cert
    if not cert_path:
        print("Missing --cert\n")
        sys.exit(1)

    ca_cert_path = args.ca_cert
    if not ca_cert_path:
        print("Missing --ca_cert\n")
        sys.exit(1)

    if not os.path.isfile(cert_path):
        raise Exception("Cert path {0} does not exist".format(cert_path))

    if not os.path.isfile(ca_cert_path):
        raise Exception("CA Cert path {0} does not exist".format(ca_cert_path))

    cert_content = open(cert_path).read().strip()
    ca_cert_content = open(ca_cert_path).read().strip()

    output_dir = SSL_CERTS_DIR

    final_cert_path = os.path.join(output_dir, "nanitor.pem")
    final_ca_cert_path = os.path.join(output_dir, "ca-cert.pem")
    final_nanitor_crt_path = os.path.join(output_dir, "nanitor.crt")

    # Process the certificate file.
    if cert_content.contains("-----BEGIN CERTIFICATE-----"):
        # Already in the right format.
        shutil.copy(cert_path, final_cert_path)
    else:
        # Not PEM format, need to convert with openssl.
        _convert_der_to_pem(cert_path, final_cert_path, args, want_output)

    # Process the CA certificate file.
    if ca_cert_content.contains("-----BEGIN CERTIFICATE-----"):
        # Already in the right format.
        shutil.copy(ca_cert_path, final_ca_cert_path)
    else:
        # Not PEM format, need to convert with openssl.
        _convert_der_to_pem(ca_cert_path, final_ca_cert_path, args, want_output)

    # Now we have both files in PEM format and need to concatenate them into nanitor.crt
    with open(final_nanitor_crt_path, "wb") as fp:
        fp.write(open(final_cert_path).read().strip() + "\n")
        fp.write(open(final_ca_cert_path).read().strip() + "\n")


def _nginx_config(args, want_output=True):
    if not os.path.isdir(NGINX_CONFIG_DIR):
        os.makedirs(NGINX_CONFIG_DIR)

    default_config = os.path.join(NGINX_CONFIG_DIR, "default.conf")
    if os.path.exists(default_config):
        os.remove(default_config)

    tpl_config = "/usr/lib/nanitor-server/share/nginx.conf"
    nginx_config = os.path.join(NGINX_CONFIG_DIR, "nanitor.conf")
    shutil.copy(tpl_config, nginx_config)


def _check_nginx_config_system_api(args, want_output=True):
    """Check current nginx config if it has system_api defined, if not we add it."""
    nginx_config = os.path.join(NGINX_CONFIG_DIR, "nanitor.conf")
    if not os.path.exists(nginx_config):
        return

    nginx_content = open(nginx_config, "rb").read().strip()
    nginx_content_lower = nginx_content.lower()

    has_system_api = NGINX_SYSTEM_API_SECTION_IDENTIFIER in nginx_content_lower
    has_collector_socket = NGINX_COLLECTOR_SOCKET_SECTION_IDENTIFIER in nginx_content_lower

    if has_system_api and has_collector_socket:
        return

    new_nginx = ""

    with open(nginx_config, "rb") as f:
        for line in f:
            line = line.rstrip()

            if "location / {" in line:
                if not has_system_api:
                    new_nginx += NGINX_SYSTEM_API_SECTION + "\n"

                if not has_collector_socket:
                    new_nginx += NGINX_COLLECTOR_SOCKET_SECTION + "\n"

            new_nginx += line + "\n"

    if not new_nginx:
        return

    with open(nginx_config, "w") as f:
        f.write(new_nginx + "\n")

    # Now needs to restart the nginx config.
    cmd = "systemctl restart nginx"
    run_command(cmd, needs_root=True, testing=args.testing)


def _run_server_management(args, want_output=True):
    manager_bin = get_manager_bin()
    run_command("{env_string} {bin} run_management".format(bin=manager_bin, env_string=get_manager_env_string()), testing=args.testing, want_output=want_output)


def _get_server_installation_id(args):
    from_var = get_envvar_case(TEST_SERVER_INSTALLATION_ID_VARIABLE)
    if from_var:
        # For testing purposes.
        return from_var

    # Normal production flow.
    cli_bin = get_cli_bin()
    cmd = "{env_string} {bin} get_server_installation_id".format(bin=cli_bin, env_string=get_cli_env_string())

    try:
        proc_ret = check_output(cmd, shell=True)
    except CalledProcessError:
        # Non-zero error code, this means we don't have a server-installation-id.
        # Normal behaviour, unprovisioned server.
        return None

    return proc_ret.strip()


def _createadmin(args):
    cli_bin = get_cli_bin()
    email = "support@nanitor.com"
    password = random_string()

    run_command('{env_string} {bin} user_create --email "{email}" --fullname "Nanitor Admin" --password {password}'
        .format(bin=cli_bin, env_string=get_cli_env_string(), email=email, password=password), testing=args.testing)

    run_command('{env_string} {bin} role_assign --email "{email}" admin'
        .format(bin=cli_bin, env_string=get_cli_env_string(), email=email), testing=args.testing)

    return dict(email=email, password=password)


def createadmin(args):
    info = _createadmin(args)
    print("Admin user created with email {0} and password: {1}".format(info['email'], info['password']))


def _create_openssl_keys(args, want_output=True):
    cmd = "openssl genrsa -out {0} 2048".format(OPENSSL_PRIVATE_KEY)
    run_command(cmd, needs_root=False, testing=args.testing, want_output=want_output)

    cmd = "openssl rsa -in {0} -out {1} -outform PEM -pubout".format(OPENSSL_PRIVATE_KEY, OPENSSL_PUBLIC_KEY)
    run_command(cmd, needs_root=False, testing=args.testing, want_output=want_output)


# Adds customer_sync to config if not there already.
def _customer_sync_add(args, want_output=True):
    if not os.path.exists(NANITOR_COMMON_INI):
        raise Exception("{cfg} does not exist".format(cfg=NANITOR_COMMON_INI))

    username = ""
    password = ""
    url_scheme = "https"

    # Try to extract the information from CentOS repos
    for repofile_path in [CENTOS_SERVER_REPO_STABLE_PATH, CENTOS_SERVER_REPO_TESTING_PATH]:
        if not os.path.isfile(repofile_path):
            continue

        ret_dict = _parse_centos_repofile(repofile_path)
        username = ret_dict["username"]
        password = ret_dict["password"]
        url_scheme = ret_dict["url_scheme"].lower()
        break

    if not username or not password:
        raise Exception("Unable to get username and password from centos repository files")

    use_http = url_scheme == "http"
    _hub_write_nanitor_common(username, password, use_http)


def enableall(args, want_output=True):
    services = " ".join(SERVICES)
    cmd = "systemctl enable {0}".format(services)
    run_command(cmd, needs_root=True, testing=args.testing, want_output=want_output)


def disableall(args, want_output=True):
    services = " ".join(SERVICES)
    cmd = "systemctl disable {0}".format(services)
    run_command(cmd, needs_root=True, testing=args.testing, want_output=want_output)


def startall(args, want_output=True):
    services = " ".join(SERVICES)
    cmd = "systemctl start {0}".format(services)
    run_command(cmd, needs_root=True, testing=args.testing, want_output=want_output)


def restartall(args, remove_nsq=False, want_output=True):
    if remove_nsq:
        run_command("systemctl stop nanitor-nsq.service", needs_root=True, testing=args.testing, want_output=want_output)
        run_command("rm -rf /var/lib/nanitor/server/nsqd/*", needs_root=True, testing=args.testing)

    services = " ".join(SERVICES)
    cmd = "systemctl restart {0}".format(services)
    run_command(cmd, needs_root=True, testing=args.testing, want_output=want_output)


def stopall(args, want_output=True):
    services = " ".join(SERVICES)
    cmd = "systemctl stop {0}".format(services)
    run_command(cmd, needs_root=True, testing=args.testing, want_output=want_output)


def statusall(args, want_output=True):
    services = " ".join(SERVICES)
    cmd = "systemctl status {0}".format(services)
    run_command(cmd, needs_root=True, testing=args.testing, want_output=want_output)


def _upgrade(args, want_output=True):
    print("Checking and upgrading Nanitor if required...")

    if _is_debian():
        _upgrade_debian(args, want_output)
    else:
        _upgrade_yum(args, want_output)

    # Run customer portal sync
    args.base_url = ""
    args.username = ""
    args.password = ""
    args.use_http = False

    print("Syncing with Nanitor Hub Now.")
    _hub_sync(args)

    print("Running management tasks.")
    _run_server_management(args)

    print("Upgrade successful.")


def _upgrade_yum(args, want_output=True):
    # Check if using http or https.
    use_http = _nanitor_common_use_http()
    server_rpm_url = get_server_rpm_url(use_http)
    ui_rpm_url = get_ui_rpm_url(use_http)

    cmd = "yum -y install {server_rpm_url} {ui_rpm_url}".format(server_rpm_url=server_rpm_url, ui_rpm_url=ui_rpm_url)
    ret = run_command(cmd, needs_root=True, testing=args.testing, want_output=want_output, ignore_error=True)
    if ret != 0:
        print("System already up to date or unable to connect to network")
        sys.exit(0)


def _upgrade_debian(args, want_output=True):
    cmd = "curl -sL -o /tmp/nanitor-server.deb https://hub.nanitor.com/files/deb/nanitor-server.deb && sudo apt install -y /tmp/nanitor-server.deb"
    ret = run_command(cmd, needs_root=True, testing=args.testing, want_output=want_output, ignore_error=True)
    if ret != 0:
        print("System already up to date or unable to connect to network")
        sys.exit(0)

    # Run customer portal sync
    args.base_url = ""
    args.username = ""
    args.password = ""
    args.use_http = False

    print("Syncing with Nanitor Hub Now.")
    _hub_sync(args)

    print("Running management tasks.")
    _run_server_management(args)

    print("Upgrade successful.")

def _check_server_certificate(args, want_output=True):
    cli_bin = get_cli_bin()
    ret = call("{env_string} {bin} check_server_certificate".format(bin=cli_bin, env_string=get_cli_env_string()), shell=True)
    if ret == 0:
        print("Certificate is fine")
    elif ret == 1:
        # Cert replaced, need to restart nginx.
        run_command("systemctl restart nginx", needs_root=True, testing=args.testing, want_output=want_output)
        print("Certificate has been updated and nginx restarted")
    elif ret == 2:
        print("Failed to check the certificate, but cannot do anything about it.")
    elif ret == 3:
        print("Certificate is not a Nanitor CA issued, not doing anything about it.")


def _check_server_upgrade(args, want_output=True):
    cli_bin = get_cli_bin()
    output = None
    try:
        output = check_output("{env_string} {bin} check_server_upgrade {components}".format(bin=cli_bin, env_string=get_cli_env_string(), components=" ".join(UPGRADE_COMPONENTS)), shell=True)
    except CalledProcessError:
        # Error code.
        print("Failed to check for server upgrades.")
        return
    packages = output.splitlines()

    if not packages:
        print("No upgrades available.")

    ret = call(["rpm", "-Uvh"] + packages)
    if ret == 0:
        print("Successfully upgraded RPM packages")
    else:
        print("Upgrading RPM packages returrned exit code %d", ret)


def config_get(config, section, key, fallback=None):
    ret = None

    try:
        ret = config.get(section, key)
    except:
        if fallback:
            return fallback

    return ret


def backup(args):
    """
    This creates a Nanitor Backup Archive from a Nanitor installation into a .tar.gz archive containing:
    metadata.json => Metadata file
    database.sql => SQL dump
    datadir.tar.gz => Archive containing the data directory.
    etc.tar.gz => Configuration files
    ssl-local.tar.gz => Nginx SSL key and certificate.
    """
    output_dir = args.output_dir
    if not os.path.isdir(output_dir):
        print("Output directory {0} doesn't exist".format(output_dir))
        return False

    output_dir = os.path.abspath(output_dir)

    # Try to recover the expected DB credentials from nanitor config.
    database_host = "localhost"
    database_name = "nanitor"
    database_username = "nanitor"
    database_password = ""

    # Get database config information from nanitor_common.ini.
    config = ConfigParser.SafeConfigParser()
    config.read(NANITOR_COMMON_INI)

    if config.has_section("database"):
        database_name = config_get(config, 'database', 'name', fallback='nanitor')
        database_username = config_get(config, 'database', 'user', fallback='nanitor')
        database_host = config_get(config, 'database', 'host', fallback='localhost')

        dbpass = config_get(config, 'database', 'password', fallback='nanitor')
        if dbpass and not dbpass.startswith('$'):
            database_password = dbpass

    if not database_password:
        print("Unable to retrieve database information from nanitor_common.ini cannot continue")
        return False

    # Create temporary directory in the output folder to write the data to.
    # We will then tar this up afterwards.
    temp_dir = os.path.join(output_dir, str(uuid4()))
    if os.path.isdir(temp_dir):
        print("Backup failed, please try again.")
        return False

    os.makedirs(temp_dir)

    # Create metadata - want version number and date in the metadata file.
    # Want output from full_version into another file.
    cli_bin = get_cli_bin()

    full_version_file = os.path.join(temp_dir, "full_version.txt")

    cmd = "{env_string} {bin} full_version > {output}".format(bin=cli_bin, env_string=get_cli_env_string(), output=full_version_file)
    run_command(cmd, needs_root=True, testing=args.testing, want_output=True)

    version = ""
    with open(full_version_file) as f:
        for line in f:
            if line.startswith("Version: "):
                components = line.strip().split("Version: ")
                if len(components) != 2:
                    print("Invalid version file")
                    return False

                version = components[1]

    # Write the metadata.
    metadata_file = os.path.join(temp_dir, "metadata.json")
    metadata = dict()
    metadata["version"] = version
    metadata["timestamp_utc"] = int(time.time())

    with open(metadata_file, "w") as f:
        json.dump(metadata, f, sort_keys=True, indent=4, separators=(',', ': '))
        f.write("\n")

    # Do a database dump.
    sql_file = os.path.join(temp_dir, "database.sql")
    _backupdb(dbhost=database_host, dbname=database_name, dbuser=database_username, dbpass=database_password, output_file=sql_file, testing=args.testing)

    # Do a copy of the data directory.
    datadir_file = os.path.join(temp_dir, "datadir.tar.gz")
    cmd = "tar -zcf {0} -C /var/lib/nanitor server".format(datadir_file)
    run_command(cmd, needs_root=True, testing=args.testing, want_output=True)

    # Do a copy of the config directory.
    etc_file = os.path.join(temp_dir, "etc.tar.gz")
    cmd = "tar -zcf {0} -C /etc nanitor".format(etc_file)
    run_command(cmd, needs_root=True, testing=args.testing, want_output=True)

    # Get the SSL Certificates
    etcssl_dir = "/etc/ssl/local"
    if os.path.isdir(etcssl_dir):
        ssllocal_file = os.path.join(temp_dir, "ssl-local.tar.gz")
        cmd = "tar -zcf {0} -C /etc/ssl local".format(ssllocal_file)
        run_command(cmd, needs_root=True, testing=args.testing, want_output=True)

    now = datetime.utcnow()
    output_file = os.path.join(output_dir, "nanitor_backup_archive_{0}.tgz".format(now.strftime("%Y%m%d%H%M%S")))

    # Now tar up the temp_dir.
    cmd = "(cd {0} && tar -zcf {1} *)".format(temp_dir, output_file)
    run_command(cmd, needs_root=True, testing=args.testing, want_output=True)

    shutil.rmtree(temp_dir)
    print("Nanitor Backup Archive (NBA) '{0}' created".format(output_file))

    return True


def restore(args):
    """
    This stores from a Nanitor Backup Archive:
    metadata.json => Metadata file
    database.sql => SQL dump
    datadir.tar.gz => Archive containing the data directory.
    """

    full_path = os.path.abspath(args.path)
    if not os.path.isfile(full_path):
        print("Nanitor Backup Archive {0} doesn't exist".format(full_path))
        return False

    if not os.path.isdir(NANITOR_ETC):
        os.makedirs(NANITOR_ETC)

    if not os.path.isdir(NANITOR_LIB_SERVER):
        os.makedirs(NANITOR_LIB_SERVER)

    temp_dir = os.path.join(NANITOR_LIB_SERVER, "temp")
    if os.path.isdir(temp_dir):
        shutil.rmtree(temp_dir)

    os.makedirs(temp_dir)
    os.chdir(temp_dir)

    cmd = "tar -zxf {0}".format(full_path)
    run_command(cmd, needs_root=True, testing=args.testing, want_output=True)

    cmd = "chown -R nanitor:nanitor {0}".format(temp_dir)
    run_command(cmd, needs_root=True, testing=args.testing, want_output=True)

    metadata_file = os.path.join(temp_dir, "metadata.json")
    metadata = json.load(open(metadata_file))

    dbdump_path = os.path.join(temp_dir, "database.sql.gz")

    print("Restoring NBA - Nanitor version: {0}".format(metadata['version']))
    print("Time of backup in UTC: {0}".format(metadata['timestamp_utc']))

    # Restore config files in /etc/.
    cmd = "tar -zxf etc.tar.gz -C /etc/"
    run_command(cmd, needs_root=True, testing=args.testing, want_output=True)

    # Restore /etc/ssl/local.
    ssllocal_path = os.path.join(temp_dir, "ssl-local.tar.gz")
    if os.path.isfile(ssllocal_path):
        cmd = "tar -zxf ssl-local.tar.gz -C /etc/ssl"
        run_command(cmd, needs_root=True, testing=args.testing, want_output=True)

    # Try to recover the expected DB credentials from nanitor config.
    database_host = "localhost"
    database_name = "nanitor"
    database_username = "nanitor"
    database_password = random_string()

    config = ConfigParser.SafeConfigParser()
    config.read(NANITOR_COMMON_INI)

    if config.has_section("database"):
        database_name = config_get(config, 'database', 'name', fallback='nanitor')
        database_username = config_get(config, 'database', 'user', fallback='nanitor')
        database_host = config_get(config, 'database', 'host', fallback='localhost')

        dbpass = config_get(config, 'database', 'password', fallback='nanitor')
        if dbpass and not dbpass.startswith('$'):
            database_password = dbpass

    # Create the database from the init file.
    _restoredb(dbhost=database_host, dbname=database_name, dbuser=database_username, dbpass=database_password, dbdump_path=dbdump_path, testing=args.testing)

    # Restore datadir files into /var/lib/nanitor/server.
    cmd = "tar -zxf datadir.tar.gz -C /var/lib/nanitor/"
    run_command(cmd, needs_root=True, testing=args.testing, want_output=True)

    cmd = "chown -R nanitor:nanitor /var/lib/nanitor/server"
    run_command(cmd, needs_root=True, testing=args.testing, want_output=True)

    return True


def _prompt_continue():
    r = raw_input("Do you want to continue with this installation? (yes/no) ")
    if r.lower() == "yes":
        return True

    return False


def _validate_arguments(argument_value, error_message="", allowed_regex=None, validate_func=None):
    success = True
    error_message = error_message if error_message else "{0} contains invalid value, aborting".format(argument_value)

    if allowed_regex:
        success = re.match(allowed_regex, argument_value)

    if success and validate_func:
        success = validate_func(argument_value)

    return dict(success=success, error_message=error_message)


def _validate_arguments_or_exit(argument_value, error_message="", allowed_regex=None, validate_func=None):
    validate_dict = _validate_arguments(argument_value, error_message=error_message, allowed_regex=allowed_regex, validate_func=validate_func)
    success = validate_dict['success']
    error_message = validate_dict['error_message']

    if not success:
        print(error_message)
        sys.exit(1)


def _prompt_value(show_input, default_value="", error_message="", allowed_regex=None, validate_func=None, password=False):
    show_input += ": "

    """Prompts for a value from stdin and returns the output"""
    if default_value:
        show_input += default_value

    while True:
        if password:
            r = getpass.getpass(show_input).strip()
        else:
            r = raw_input(show_input).strip()

        validate_dict = _validate_arguments(r, error_message=error_message, allowed_regex=allowed_regex, validate_func=validate_func)
        if not validate_dict["success"]:
            print("Input error, please try again: {0}".format(validate_dict["error_message"]))
            continue

        # Success.
        return r


def _server_install(args):
    print("Welcome to the Nanitor auto installer. We will first print the settings for you to make sure the configuration is correct.")

    server_url = _get_server_url(args)
    print("Server Hostname: {0}".format(args.full_hostname))
    print("Server Management URL: {0}".format(server_url))
    print("Server Agent URL: {0}/api".format(server_url))

    if not args.yes:
        if not _prompt_continue():
            print("Installation aborted")
            sys.exit(0)

    print("Nanitor clean OEM Installation has started")

    # Make sure our repositories only point to the Nanitor HUB.
    if not _is_debian():
        _set_yum_repositories(args)

    # Reseed the SSH keys if they contain the known MD5 sum of /etc/ssh/ssh_host_rsa_key.
    ssh_rsa_key_path = "/etc/ssh/ssh_host_rsa_key"
    if os.path.isfile(ssh_rsa_key_path):
        known_md5_sums = ["6efd06a9d621d1d9dfd80034ca5ac84e"]
        ssh_rsa_key_hash = _md5_path(ssh_rsa_key_path)
        if ssh_rsa_key_hash in known_md5_sums:
            run_command("rm -f /etc/ssh/*key*", needs_root=True, testing=args.testing)
            run_command("service sshd restart", needs_root=True, testing=args.testing)

    if not _is_debian():
        print("Checking and installing VMware tools...")
        _install_guest_tools(args, want_output=False)

    # Install latest Nanitor
    print("Checking and upgrading Nanitor is required...")
    _upgrade(args, want_output=False)

    """Clean install"""
    print("Installing the Nanitor database")
    _initdb(args)
    _migratedb(args, want_output=False)
    _testdb(args)

    print("Creating SSL certificate...")
    _create_openssl_keys(args, want_output=False)
    _create_csr(args, want_output=False)

    print("Starting an enabling services...")
    startall(args, want_output=False)
    enableall(args, want_output=False)

    # Create admin user.
    print("Creating admin user...")
    info = _createadmin(args)

    out_dict = dict()

    output_file = os.path.abspath(NANITOR_SERVER_INSTALL_OUT)

    server_installation_id = _get_server_installation_id(args)

    server_url = _get_server_url(args)

    print("Preparing server config...")
    _set_server_url(args, want_output=False)
    _nginx_config(args, want_output=False)

    # Syncing with the Nanitor Hub and getting certificates in place.
    print("Running post install tasks...")
    _post_install(args)

    print("Installer output has been written to: {0}".format(output_file))

    out_dict['admin_email'] = info['email']
    out_dict['admin_password'] = info['password']
    out_dict['server_installation_id'] = "SID-{0}".format(server_installation_id)
    out_dict['server_url'] = server_url

    print("Created nanitor admin with email '{0}' and password '{1}'".format(info['email'], info['password']))
    print("Server installation ID is: {0}".format(server_installation_id))
    print("Server URL will be: {0}".format(server_url))
    print("Nanitor Admin Email Login: {0}".format(out_dict['admin_email']))
    print("Nanitor Admin Password: {0}".format(out_dict['admin_password']))
    print("Please use these credentials to login into: {0}".format(server_url))

    with open(output_file, 'wb') as fp:
        json.dump(out_dict, fp, sort_keys=True, indent=4, separators=(',', ': '))
        fp.write("\n")

    print("Nanitor server installed and up and running at: {0}".format(server_url))

    return True



def _get_hypervisor():
    ret = dict(is_vmware=False, is_hyperv=False)

    cmd = "dmidecode -t system|grep 'Manufacturer\|Product'"
    cmd_out = check_output(cmd, shell=True).strip()
    output_lines = cmd_out.split(":", 1)
    if len(output_lines) != 2:
        # Unknown, cannot determine hypervisor.
        return ret

    manufacturer = ""
    product_name = ""

    for output_line in output_lines:
        output_line = output_line.strip().lower()
        key_values = cmd_out.split(":", 1)
        if len(key_values) != 2:
            continue

        key = key_values[0].strip().lower()
        val = key_values[1].strip().lower()

        if key == "manufacturer":
            manufacturer = val
        elif key == "product name":
            product_name = val

    if "vmware" in manufacturer:
        ret['is_vmware'] = True

    if "microsoft" in manufacturer:
        ret['is_hyperv'] = True

    ret["product_name"] = product_name

    return ret


def _install_guest_tools(args, want_output=False):
    # Installing guest-tools if there is a hyper-visor.
    hypervisor_info = _get_hypervisor()
    if hypervisor_info["is_vmware"]:
        print("Installing VMware tools if not currently installed")
        run_command("yum -y install open-vm-tools", needs_root=True, testing=args.testing, want_output=want_output)
        run_command("systemctl enable vmtoolsd", needs_root=True, testing=args.testing, want_output=want_output)
        run_command("systemctl start vmtoolsd", needs_root=True, testing=args.testing, want_output=want_output)
    elif hypervisor_info["is_hyperv"]:
        print("Installing HyperV tools if not currently installed")
        run_command("sudo yum -y install hyperv-daemons", needs_root=True, testing=args.testing, want_output=want_output)
        run_command("systemctl enable hypervvssd", needs_root=True, testing=args.testing, want_output=want_output)
        run_command("systemctl start hypervvssd", needs_root=True, testing=args.testing, want_output=want_output)


# Post install syncs the Nanitor Hub and starts nginx.
def _post_install(args, want_output=False):
    # Syncing the Nanitor Hub first.
    args.base_url = ""
    args.username = ""
    args.password = ""
    args.use_http = False

    run_command("chown nanitor:nanitor {0}".format(NANITOR_CSR_PATH), needs_root=True, testing=args.testing, want_output=want_output)

    print("Syncing with the Nanitor hub, this can take a few minutes please wait.....")

    _hub_sync(args)

    print("Finished syncing, finishing remaining tasks.")

    if not os.path.isfile(NANITOR_FULLCERT_PATH):
        print("Done sync with HUB but got no certificate, path does not exist: {0}".format(NANITOR_FULLCERT_PATH))
        sys.exit(1)

    # Now copy the SSL certificates in place.
    shutil.copy(NANITOR_FULLCERT_PATH, SSL_FULLCERT_PATH)

    # Starting nginx.
    run_command("systemctl enable nginx.service", testing=args.testing, needs_root=True)
    run_command("service nginx start", testing=args.testing, needs_root=True)
    run_command("service nginx restart", testing=args.testing, needs_root=True)

    print("Post-install script has been completed succesfully")

    return True


def _md5_path(fname):
    hash_md5 = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()


def _configure_mail_relay(args):
    if args.address:
        _validate_arguments_or_exit(args.address, error_message="address cannot be blank", validate_func=_is_not_blank)
    else:
        args.address = _prompt_value("Enter address for mail relay (e.g. 172.16.20.200)", error_message="Address cannot be blank", validate_func=_is_not_blank)

    run_command("postconf -e 'inet_protocols = ipv4'", testing=args.testing, needs_root=True)
    run_command("postconf -e 'relayhost = {0}'".format(args.address), testing=args.testing, needs_root=True)
    run_command("service postfix restart", testing=args.testing, needs_root=True)

    return True


def _is_not_blank(s):
    return len(s.strip()) > 0


def _is_valid_fqdn(fqdn):
    if len(fqdn.split(".")) < 3:
        return False

    return re.match("(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$)", fqdn)


def _is_valid_dnslist(dnslist):
    for dns in dnslist.strip().split():
        if not _is_valid_ipv4_address(dns):
            return False

    return True


def _is_valid_cidr_network(address):
    if len(address.split("/")) < 2:
        return False

    return re.match("^([0-9]{1,3}\.){3}[0-9]{1,3}(\/([0-9]|[1-2][0-9]|3[0-2]))?$", address)


def _is_valid_ipv4_address(address):
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:  # no inet_pton here, sorry
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        return address.count('.') == 3
    except socket.error:  # not a valid address
        return False

    return True


# Not all commands require the hostname variables.
def _populate_hostname_variables(args):
    args.full_hostname = _get_hostname()
    if _is_debian():
        args.full_hostname = _get_hostname() + ".nanitor.net"
    args.nanitor_hostname = getattr(args, 'nanitor_hostname', '')

    if not args.nanitor_hostname:
        args.nanitor_hostname = args.full_hostname

    if not _is_valid_fqdn(args.full_hostname):
        print("full_hostname {0} is not a fully qualified domain name should be e.g. nan-prod-serv01.nanitor.net".format(args.full_hostname))
        sys.exit(1)

    if not _is_valid_fqdn(args.nanitor_hostname):
        print("nanitor_hostname {0} is not a fully qualified domain name".format(args.nanitor_hostname))
        sys.exit(1)


def _is_debian():
    return os.path.isfile('/etc/debian_version')


def _is_valid_proxy_url(proxy_url):
    url_components = proxy_url.split(":")
    if len(url_components) == 0:
        return False

    return True


# -https_proxy --https_proxy
# Writes /etc/environment proxy settings at the end, also sources it into the current environment.
def _configure_proxy(args):
    if args.http:
        _validate_arguments_or_exit(args.http, error_message="http is not a valid proxy URL", validate_func=_is_valid_proxy_url)
    else:
        args.http = _prompt_value("Enter valid HTTP proxy URL (e.g. http://proxy.company.com:8080)", error_message="Invalid proxy URL", validate_func=_is_valid_proxy_url)

    if args.https:
        _validate_arguments_or_exit(args.https, error_message="https is not a valid proxy URL", validate_func=_is_valid_proxy_url)
    else:
        args.https = _prompt_value("Enter valid HTTPS proxy URL (if empty defaults to {0})".format(args.http), error_message="Invalid proxy URL", validate_func=_is_valid_proxy_url)

    lines = []

    no_proxy_found = False

    if os.path.isfile(ENVIRONMENT_PATH):
        with open(ENVIRONMENT_PATH, "rb") as fp:
            skip_line = False

            for line in fp:
                line = line.strip()
                if "http_proxy=" in line:
                    skip_line = True
                elif "https_proxy=" in line:
                    skip_line = True
                elif "no_proxy=" in line:
                    no_proxy_found = True
                    skip_line = False

                if not skip_line:
                    lines.append(line)

    lines.append('http_proxy="{0}"'.format(args.http))
    lines.append('https_proxy="{0}"'.format(args.https))
    if not no_proxy_found:
        no_proxy = '"127.0.0.1, localhost"'
        os.environ["no_proxy"] = no_proxy
        lines.append('no_proxy={0}'.format(no_proxy))

    os.environ["http_proxy"] = args.http
    os.environ["https_proxy"] = args.https

    with open(ENVIRONMENT_PATH, "wb") as fp:
        for line in lines:
            fp.write(line + "\n")

    return True


def _configure_hub(args):
    if args.username:
        _validate_arguments_or_exit(args.username, error_message="Username cannot be blank", validate_func=_is_not_blank)
    else:
        args.username = _prompt_value("Enter HUB username", error_message="Usernamecannot be blank, invalid format", validate_func=_is_not_blank)

    if args.password:
        _validate_arguments_or_exit(args.password, error_message="Password cannot be blank", validate_func=_is_not_blank)
    else:
        args.password = _prompt_value("Enter HUB password", error_message="Password cannot be blank, invalid format", validate_func=_is_not_blank, password=True)

    url_scheme = "https"
    if args.use_http:
        url_scheme = "http"

    full_url = "{url_scheme}://hub.nanitor.com/api/customer_signin_info".format(url_scheme=url_scheme)

    success = False

    auth_string = base64.b64encode('{0}:{1}'.format(args.username, args.password))

    # Test these credentials first.
    hub_req = urllib2.Request(full_url)
    hub_req.add_header("Authorization", "Basic {0}".format(auth_string))

    try:
        hub_resp = urllib2.urlopen(hub_req)
        html = hub_resp.read()
        if "username" in html:
            success = True
    except:
        success = False

    if not success:
        print("Failed to connect to the Nanitor HUB to check YUM packages, unable to connect or invalid credentials?")
        sys.exit(1)

    # Also do a provision check on the Nanitor HUB.
    full_url = "{url_scheme}://hub.nanitor.com/api/server_check_provision".format(url_scheme=url_scheme)
    payload_dict = {}
    payload_dict["hostname"] = args.full_hostname

    server_installation_id = _get_server_installation_id(args)
    if server_installation_id:
        payload_dict["server_installation_id"] = server_installation_id

    payload = json.dumps(payload_dict)
    hub_req = urllib2.Request(full_url, payload, {'Content-Type': 'application/json', 'Content-Length': len(payload) })
    hub_req.add_header("Authorization", "Basic {0}".format(auth_string))

    message = ""

    try:
        hub_resp = urllib2.urlopen(hub_req)
        json_data = json.loads(hub_resp.read())
        success = json_data['success']
        message = json_data['message']
    except:
        success = False

    if not success:
        print("Failed to connect to the Nanitor HUB to check provision state, unable to connect or invalid credentials?: Detailed err: '{0}'".format(message))
        sys.exit(1)

    _hub_write_nanitor_common(args.username, args.password, args.use_http)

    return True


# Write the Nanitor Hub information into nanitor_common.ini
def _hub_write_nanitor_common(hub_username, hub_password, use_http):
    config = ConfigParser.SafeConfigParser()
    config.read(NANITOR_COMMON_INI)

    section_name = "customer_portal"

    if not config.has_section(section_name):
        config.add_section(section_name)

    config.set(section_name, "sync", "true")
    config.set(section_name, "username", hub_username)
    config.set(section_name, "password", hub_password)

    if use_http:
        config.set("customer_portal", "use_http", "true")
    else:
        config.remove_option("customer_portal", "use_http")

    with open(NANITOR_COMMON_INI, "w+") as configfile:
        config.write(configfile)


# Check the use_http flag if we use http or https.
def _nanitor_common_use_http():
    config = ConfigParser.SafeConfigParser()
    config.read(NANITOR_COMMON_INI)

    section_name = "customer_portal"
    if not config.has_section(section_name):
        return False

    option_name = 'use_http'
    if not config.has_option(section_name, option_name):
        return False

    val_lower = config.get("customer_portal", option_name)
    return val_lower in ["true", "yes"]


def _get_dns_domain(full_hostname):
    return full_hostname.partition('.')[2]


def _configure_hostname(args):
    if args.full_hostname:
        _validate_arguments_or_exit(args.full_hostname, error_message="full_hostname does is not a fully qualified domain name", validate_func=_is_valid_fqdn)
    else:
        args.full_hostname = _prompt_value("Enter Full hostname for this server (FQDN) (e.g. nan-srv1.)", error_message="Invalid fully qualified domain name", validate_func=_is_valid_fqdn)

    # Set the hostname
    run_command("hostnamectl set-hostname {0}".format(args.full_hostname), needs_root=True, testing=args.testing)


    print("----- Hostname Settings -----")
    print("Full hostname: {0}".format(args.full_hostname))

    return True


def _configure_network(args):
    if args.address:
        _validate_arguments_or_exit(args.address, error_message="address is not a valid CIDR address", validate_func=_is_valid_cidr_network)
    else:
        args.address = _prompt_value("Enter IP Address in CIDR format (e.g. 172.16.20.4/24)", error_message="Invalid CIDR address", validate_func=_is_valid_cidr_network)

    if args.gateway:
        _validate_arguments_or_exit(args.gateway, error_message="gateway is not a valid IP address", validate_func=_is_valid_ipv4_address)
    else:
        args.gateway = _prompt_value("Enter IP gateway address (e.g. 172.16.20.1)", error_message="Invalid CIDR address", validate_func=_is_valid_ipv4_address)

    if args.dns:
        _validate_arguments_or_exit(" ".join(args.dns), error_message="DNS contains invalid IP address", validate_func=_is_valid_dnslist)
    else:
        dns_list = _prompt_value("Enter DNS servers, can be one or more space separated (e.g. 172.16.20.15 172.16.20.16)", error_message="Invalid DNS", validate_func=_is_valid_dnslist)
        args.dns = dns_list.split()

    address = args.address
    prefix = 0
    gateway = args.gateway
    dns_domain = _get_dns_domain(args.full_hostname)

    address_components = address.split("/", 1)
    if len(address_components) != 2:
        print("Invalid address (should be in CIDR format e.g. 172.16.20.4/24): {0}".format(address))
        sys.exit(1)

    if not address_components[1].isdigit():
        # Invalid prefix
        print("Invalid address, invalid network prefix (should be in CIDR format e.g. 172.16.20.4/24): {0}".format(address))
        sys.exit(1)


    ip_address = address_components[0]
    prefix = int(address_components[1])

    if not _is_valid_ipv4_address(ip_address):
        print("Invalid ip address {0}".format(ip_address))
        sys.exit(1)

    if prefix < 1 or prefix >= 32:
        print("Invalid network prefix {0}".format(prefix))
        sys.exit(1)

    if not _is_valid_ipv4_address(gateway):
        print("Invalid gateway IP address {0}".format(gateway))
        sys.exit(1)

    with open(IFCFG_NETWORK_PATH, 'wb') as fp:
        fp.write(IFCFG_NETWORK_TEMPLATE.format(gateway=gateway, address=ip_address, prefix=prefix))
        fp.write("\n")


    resolv_conf_str = ""

    if dns_domain:
        resolv_conf_str += "search {dns_domain}\n".format(dns_domain=dns_domain)

    for dns in args.dns:
        resolv_conf_str += "nameserver {dns}\n".format(dns=dns)

    with open(RESOLVCONF_PATH, 'wb') as fp:
        fp.write(resolv_conf_str)
        fp.write("\n")

    run_command("service network restart", needs_root=True, testing=args.testing, want_output=False)

    print("----- Network Settings -----")
    print("Full hostname: {0}".format(args.full_hostname))
    print("Address: {0}".format(args.address))
    print("Gateway: {0}".format(args.gateway))
    print("DNS: {0}".format(" ".join(args.dns)))
    print("DNS domain: {0}".format(dns_domain))

    return True


def run():
    def exit_on_int(sig, frame):
        print()
        sys.exit(128 + sig)
    signal.signal(signal.SIGINT, exit_on_int)

    parser = argparse.ArgumentParser(description='Nanitor setup tool')
    subparsers = parser.add_subparsers(dest='cmd')
    subparsers.required = True

    parser.add_argument('--testing', dest='testing', action='store_true', help='Run in testing environment')
    parser.add_argument('--yes', dest='yes', action='store_true', help='Answer yes and never prompt for confirmation')

    subparsers.add_parser('testdb')
    subparsers.add_parser('initdb')
    subparsers.add_parser('create_csr')
    subparsers.add_parser('nginx_config')
    subparsers.add_parser('set_yum_repositories')
    subparsers.add_parser('system_config_migration')
    subparsers.add_parser('set_server_url')
    subparsers.add_parser('migratedb')
    subparsers.add_parser('customer_portal_sync')
    subparsers.add_parser('run_server_management')
    subparsers.add_parser('createadmin')
    subparsers.add_parser('openssl_key_regenerate')
    subparsers.add_parser('customer_sync_add')
    subparsers.add_parser('systemctl_enable')
    subparsers.add_parser('systemctl_disable')
    subparsers.add_parser('systemctl_restart')
    subparsers.add_parser('systemctl_start')
    subparsers.add_parser('systemctl_stop')
    subparsers.add_parser('systemctl_status')
    subparsers.add_parser('nsq_clean')
    subparsers.add_parser('server_install')
    subparsers.add_parser('post_install')
    subparsers.add_parser('upgrade')
    subparsers.add_parser('check_server_certificate')
    subparsers.add_parser('check_server_upgrade')

    backup_parser = subparsers.add_parser('backup')
    backup_parser.add_argument('--output_dir', dest='output_dir', type=str, help='Output directory, must exist', required=True)

    restore_parser = subparsers.add_parser('restore')
    restore_parser.add_argument('--path', dest='path', type=str, help='Full path to backup archive', required=True)

    test_ldap_parser = subparsers.add_parser('test_ldap')
    test_ldap_parser.add_argument('--domain', dest='domain', type=str, help='Domain name')
    test_ldap_parser.add_argument('--username', dest='username', type=str, help='Username')

    # Configure HUB and put into nanitor_common.ini and YUM repo
    configure_hub = subparsers.add_parser('configure_hub')
    configure_hub.add_argument('--username', dest='username', type=str, help='Username')
    configure_hub.add_argument('--password', dest='password', help='Password, if not specified it will be prompted for')
    configure_hub.add_argument('--use_http', dest='use_http', action='store_true', help='Use HTTP instead of HTTPS, not recommended')

    # hub_sync is the way to trigger sync with the Nanitor Hub.
    hub_sync = subparsers.add_parser('hub_sync')
    hub_sync.add_argument('--username', dest='username', type=str, help='Username, if not specified will use from nanitor_common.ini')
    hub_sync.add_argument('--password', dest='password', type=str, help='Password, if not specified will use from nanitor_common.ini')
    hub_sync.add_argument('--base_url', dest='base_url', type=str, help='Base URL, if not specified will use from nanitor_common.ini')
    hub_sync.add_argument('--use_http', dest='use_http', action='store_true', help='Use HTTP for syncing, if not specified will use from nanitor_common.ini')

    # Backwards compatibility to sync with the hub, will be removed soon.
    customer_portal_sync = subparsers.add_parser('customer_portal_sync')
    customer_portal_sync.add_argument('--username', dest='username', type=str, help='Username, if not specified will use from nanitor_common.ini')
    customer_portal_sync.add_argument('--password', dest='password', type=str, help='Password, if not specified will use from nanitor_common.ini')
    customer_portal_sync.add_argument('--base_url', dest='base_url', type=str, help='Base URL, if not specified will use from nanitor_common.ini')
    customer_portal_sync.add_argument('--use_http', dest='use_http', action='store_true', help='Use HTTP for syncing, if not specified will use from nanitor_common.ini')

    server_install = subparsers.add_parser('server_install')
    server_install.add_argument('--nanitor_hostname', dest='nanitor_hostname', type=str, help='If provided, this will be used to generate the Nanitor API URL for agents, defaults to system FQDN hostname.')

    create_csr = subparsers.add_parser('create_csr')
    create_csr.add_argument('--nanitor_hostname', dest='nanitor_hostname', type=str, help='If provided, this will be used to generate the Nanitor API URL for agents, defaults to system FQDN hostname.')

    set_server_url = subparsers.add_parser('set_server_url')
    set_server_url.add_argument('--nanitor_hostname', dest='nanitor_hostname', type=str, help='If provided, this will be used to generate the Nanitor API URL for agents, defaults to system FQDN hostname.')

    cert_process = subparsers.add_parser('cert_process')
    cert_process.add_argument('--cert', dest='cert', type=str, help='Full path to certificate generated by CA in PEM or DER format')
    cert_process.add_argument('--ca_cert', dest='ca_cert', type=str, help='Full path to CA certificate of the authority in PEM or DER format')

    subparsers.add_parser('nginx_config')

    configure_hostname = subparsers.add_parser('configure_hostname')
    configure_hostname.add_argument('--full_hostname', dest='full_hostname', type=str, help='Full hostname for this server.')

    configure_network = subparsers.add_parser('configure_network')
    configure_network.add_argument('--address', dest='address', type=str, help='IP address in CIDR format e.g. 172.16.20.21/24 or 172.16.20.21/28')
    configure_network.add_argument('--gateway', dest='gateway', type=str, help='IP Gateway e.g. 172.16.20.1')
    configure_network.add_argument('--dns', dest='dns', action='append', type=str, help='DNS, can be specified multiple times --dns dns1.com --dns dns2.com')

    configure_mail_relay = subparsers.add_parser('configure_mail_relay')
    configure_mail_relay.add_argument('--address', dest='address', type=str, help='Fully qualified domain name or IP address of the SMTP relay')

    configure_proxy = subparsers.add_parser('configure_proxy')
    configure_proxy.add_argument('--http', dest='http', type=str, help='HTTP proxy settings')
    configure_proxy.add_argument('--https', dest='https', type=str, help='HTTPS proxy settings, if empty and http is set, this will be set the same as http')

    success = True

    args = parser.parse_args()

    if not args.testing and os.geteuid() != 0:
        print("You need to have root privileges to run this script.")
        sys.exit(1)

    if args.cmd == 'testdb':
        testdb(args)
    elif args.cmd == 'test_ldap':
        test_ldap(args, want_output=True)
    elif args.cmd == 'initdb':
        _initdb(args)
        print("Created postgresql database user nanitor and nanitor_common.ini updated. Make sure the nanitor database in postgresql is set to md5 authentication")
    elif args.cmd == 'migratedb':
        _migratedb(args)
    elif args.cmd == 'hub_sync':
        _hub_sync(args)
    elif args.cmd == 'customer_portal_sync':
        _hub_sync(args)
    elif args.cmd == 'nginx_config':
        _nginx_config(args)
    elif args.cmd == 'set_yum_repositories':
        _set_yum_repositories(args)
    elif args.cmd == 'system_config_migration':
        # At the moment only checks nginx configs.
        _check_nginx_config_system_api(args)
    elif args.cmd == 'set_server_url':
        _populate_hostname_variables(args)
        _set_server_url(args)
    elif args.cmd == 'cert_process':
        _cert_process(args)
        print("Certification has been generated and put in place, now you can run: service nginx restart")
    elif args.cmd == 'run_server_management':
        _run_server_management(args)
    elif args.cmd == 'createadmin':
        info = _createadmin(args)
        print("Admin user created with email {0} and password: {1}".format(info['email'], info['password']))
    elif args.cmd == 'openssl_key_regenerate':
        _create_openssl_keys(args, want_output=False)
    elif args.cmd == 'customer_sync_add':
        _customer_sync_add(args, want_output=False)
    elif args.cmd == 'create_csr':
        # Requires the hostname variables for CN and subjectAltName.
        _populate_hostname_variables(args)
        csr_dict = _create_csr(args)
        print("Created CSR request ready for certification authority at: {0}".format(csr_dict['csr_file']))
    elif args.cmd == 'systemctl_enable':
        enableall(args)
    elif args.cmd == 'systemctl_disable':
        disableall(args)
    elif args.cmd == 'systemctl_start':
        startall(args)
    elif args.cmd == 'systemctl_stop':
        stopall(args)
    elif args.cmd == 'systemctl_restart':
        restartall(args, remove_nsq=False)
    elif args.cmd == 'systemctl_status':
        statusall(args)
    elif args.cmd == 'nsq_clean':
        restartall(args, remove_nsq=True)
    elif args.cmd == 'upgrade':
        _upgrade(args, want_output=False)
    elif args.cmd == 'check_server_certificate':
        _check_server_certificate(args, want_output=False)
    elif args.cmd == 'check_server_upgrade':
        _check_server_upgrade(args, want_output=False)
    elif args.cmd == 'backup':
        success = backup(args)
    elif args.cmd == 'restore':
        success = restore(args)
    elif args.cmd == 'server_install':
        _populate_hostname_variables(args)
        success = _server_install(args)
    elif args.cmd == 'configure_hostname':
        success = _configure_hostname(args)
    elif args.cmd == 'configure_network':
        _populate_hostname_variables(args)
        success = _configure_network(args)
    elif args.cmd == 'configure_hub':
        args.nanitor_hostname = ""
        _populate_hostname_variables(args)
        success = _configure_hub(args)
    elif args.cmd == 'configure_mail_relay':
        success = _configure_mail_relay(args)
    elif args.cmd == 'configure_proxy':
        success = _configure_proxy(args)

    if not success:
        print("Command failed, exiting with failure status")
        sys.exit(1)

if __name__ == '__main__':
    run()

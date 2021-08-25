# Vault Plugin: Centrify PAS Secrets Backend

This is a backend plugin to be used with [HashiСorp Vault][vault-gh].

## Quick Links
 - Vault Website: https://www.vaultproject.io
 - Main Project Github: https://www.github.com/hashicorp/vault

## Table of Contents

- [Getting Started](#getting-started)
- [Prerequisites](#prerequisites)
- [Setup](#setup)
- [Usage](#usage)
- [Developing](#developing)

## Getting Started

This is a [Vault plugin][vault-plugins] and is meant to work with Vault. This guide
assumes you have already installed Vault and have a basic understanding of how Vault
works.

Otherwise, read this guide first on how to [get started with Vault][vault-get-started].

To learn specifically about how plugins work, see documentation on [Vault plugins][vault-plugins].

## Prerequisites

### The Centrify PAS Auth Plugin

Before using this plugin, make sure that you have enabled and configured latest [auth backend
plugin from Centrify](https://github.com/centrify/vault-plugin-auth-hashicorp) first.

We do also support users logged in using another backend. This feature called "proxy mode".
Read more about how to configure proxy mode in the [Setup](#setup) section of this doc.

### The Centrify Client

**Important Note:** All Vault related communication with the Centrify Client requires either
superuser/root user or user "vault". Since this plugin is part of the Vault server, you need
to run the server as one of mentioned users, either privileged user or "vault" user.

The plugin requires the Centrify Client to be installed and running. The version 21.5 or higer
is required. You can get installation package from your tenant web UI in section "Downloads".
After installing it, the client needs to be enrolled to the desired tenant with an enrollment
code and Delegated Machine Credentials (DMC) feature enabled.

The enrollment code should be created in your tenant in Settings -> Enrollemnt -> Enrollment
Codes.

Now that everything is ready, you can enroll your machine. To do that, run:
```
# Using long names for flags:
$ sudo cenroll \
    --tenant=https://<your tenant URL> \
    --code=<your enrollment code> \
    --features=all \
    --verbose

# Using short names for flags:
$ sudo cenroll -t=https://<your tenant URL> -c=<your enrollment code> -F=all -V
```

Note that features flag is set to `all`, which means that all features will be enabled. You
can limit it to DMC feature only, by setting feature flag to `dmc`, i.e. pass `--features=dmc`.

Check if your machine is enrolled using `cinfo`:
```
$ sudo cinfo
```

Unenroll with `cunenroll`:
```
$ sudo cunenroll --machine --delete
```

More info at https://centrify.force.com/support/Article/HOWTO-Enroll-a-Centrify-Client-for-Linux-and-Enabling-AgentAuth/

## Setup

1. Enable the Plugin

```
# First, make sure plugin is registered and available in the catalog:
$ vault plugin list | grep centrify_secrets

# Now enable the plugin:
$ vault secrets enable -path=centrify centrify_secrets

# After that you can check the list of enables secrets plugins:
$ vault secrets list
```

*Note:* the path set via `-path` flag can be set to any arbitrary value, but keep in mind
that changing path will require changes in policy and all calls via CLI or REST defined
below to use that new path.

2. Add Vault Policy

You need to write a policy which will allow access to Centrify PAS secrets paths and
operations. After that, make sure your user token has the correct policies assigend.

Example:
```
# Create a new file with policy
$ tee all_users_policy.hcl << END
path "centrify/*" {
  capabilities = ["create", "update", "read", "delete",  "list"]
}
END

# Login to Vault as an administrator
$ vault login <your HashiVault root password. Usually just root for dev environment>

# Upload policy to Vault
$ vault policy write all_users ./all_users_policy.hcl

# Configure auth backend to attach that policy on users log in
$ vault write auth/centrify/config policies=all_users
```

3. Configure Proxy Mode

Proxy mode is a feature that allows users authenticated by other than Centrify PAS Auth
backend system, i.e. non-PAS users, to access information stored in Centrify PAS. Proxy
mode is enabled by default. 

To enable proxy mode use:
```
$ vault write centrify/config proxy_mode=true
```

To disable proxy mode use:
```
$ vault write centrify/config proxy_mode=false
```

4. Log REST API calls

You can enable logging of all REST API calls to the Centrify PAS system. Since name of
the secret for some requests is part of the URL, the logger will not include that part
in output for security reasons.

This feature is disabled by default. 

To enable it use:
```
$ vault write centrify/config http_logs=true
```

To disable logging of API requests use:
```
$ vault write centrify/config http_logs=false
```

## Usage

Note: Before using the plugin, make sure that you are logged in as PAS user
or as non-PAS user, but with proxy mode enabled. Also, for REST API examples
environment variables VAULT_ADDR and VAULT_TOKEN must be set.


1. Add a new secret

```
# This will add the "frodo" secret to "thering" directory
# with one key/vaule pair.

# Using CLI:
$ vault write centrify/thering/frodo secret="do not tell anyone"
Success! Data written to: centrify/thering/frodo
$

# Or the same, but using REST API:
$ curl \
    --request POST \
    --header "X-Vault-Token:${VAULT_TOKEN}" \
    --header "Content-Type: application/json" \
    --data '{"secret":"do not tell anyone"}' \
    "${VAULT_ADDR}/v1/centrify/thering/frodo"
$
```

2. Read the secret

```
# Using CLI:
$ vault read centrify/thering/frodo
Key       Value
---       -----
secret    do not tell anyone
$

# Or the same, but using REST API:
$ curl \
    --request GET \
    --header "X-Vault-Token:${VAULT_TOKEN}" \
    --header "Content-Type: application/json" \
    "${VAULT_ADDR}/v1/centrify/thering/frodo"
{"request_id":"959797a4-5e2e-0a06-13d8-b54a641ea92e","lease_id":"","renewable":false,"lease_duration":0,"data":{"secret":"do not tell anyone"},"wrap_info":null,"warnings":null,"auth":null}
$
```

3. Update the secret

```
# Using CLI:
$ vault write centrify/thering/frodo secret="do not tell Sam"
Success! Data written to: centrify/thering/frodo
$

# Or the same, but using REST API:
$ curl \
    --request POST \
    --header "X-Vault-Token:${VAULT_TOKEN}" \
    --header "Content-Type: application/json" \
    --data '{"secret":"do not tell Sam"}' \
    "${VAULT_ADDR}/v1/centrify/thering/frodo"
$
```

4. List all secrets in directory:

```
# Using CLI:
$ vault list centrify/thering
Keys
----
frodo
merry
pippin
sam
$

# Or the same, but using REST API:
$ curl \
    --request LIST \
    --header "X-Vault-Token:${VAULT_TOKEN}" \
    --header "Content-Type: application/json" \
    "${VAULT_ADDR}/v1/centrify/thering"
{"request_id":"803fcec0-3563-dc92-2cc4-a5731df59f98","lease_id":"","renewable":false,"lease_duration":0,"data":{"keys":["sam","merry","pippin","frodo"]},"wrap_info":null,"warnings":null,"auth":null}
$
```

5. Delete the secret:

```
# Using CLI:
$ vault delete centrify/thering/pippin
Success! Data deleted (if it existed) at: centrify/thering/pippin
$

# Or the same, but using REST API:
$ curl \
    --request DELETE \
    --header "X-Vault-Token:${VAULT_TOKEN}" \
    --header "Content-Type: application/json" \
    "${VAULT_ADDR}/v1/centrify/thering/pippin"
$
```

6. Read the plugin version:

```
# Using CLI:
$ vault read centrify/version
Key               Value
---               -----
git_commit        49ab1f6be9f4096d42939d6998993845a0d1b6f2
go_version        go1.16.5
os_arch           linux/amd64
plugin_version    v0.1.0
$

# Or the same, but using REST API:
$ curl \
    --request GET \
    --header "X-Vault-Token:${VAULT_TOKEN}" \
    --header "Content-Type: application/json" \
    "${VAULT_ADDR}/v1/centrify/version"
{"request_id":"8900ea92-7d85-168a-e324-e7e96bc2dee0","lease_id":"","renewable":false,"lease_duration":0,"data":{"git_commit":"49ab1f6be9f4096d42939d6998993845a0d1b6f2","go_version":"go1.16.5","os_arch":"linux/amd64","plugin_version":"v0.1.0"},"wrap_info":null,"warnings":null,"auth":null}
$
```

## Developing

If you wish to work on this plugin, you'll first need [Go][go] installed on your machine
(version 1.16+ is *required*).

Set the directory where to save the plugin:
```
$ export VAULT_PLUGINS_DIR="/tmp/vault-plugins"
```

Build the plugin:
```
$ make dev BINDIR=${VAULT_PLUGINS_DIR}
```

For local development, you can run Vault server in development mode:
```
$ sudo vault server \
    -dev \
    -dev-root-token-id=root \
    -dev-no-store-token \
    -dev-plugin-dir=${VAULT_PLUGINS_DIR} \
    -log-level=debug
```

Note that running the Vault server as privileged user (using `sudo`) is required for
communication with the Centrify Client.

Now you can enable the plugin:
```
$ vault secrets enable -path=centrify centrify_secrets
```

Verify plugin version using:
```
$ vault read centrify/version
```

### Testing

Prepare test configuration file:
```
$ cat <<EOF > ./testconfig.json
{
  "TenantURL": "<tenant_url>",
  "Marks": ["integration"],
  "ClientID": "<client_id>",
  "ClientSecret": "<client_secret>",
  "AppID": "<app_id>",
  "Scope": "<scope>",
  "PASuser": { "Username": "<username>", "Password": "<password>" },
  "PolicyChangeUser": { "Username": "<username>", "Password": "<password>" },
  "HTTPProxyURL": "<proxy-url>"
}
EOF
```

Run the tests:
```
$ make test
```


[vault-gh]: https://www.github.com/hashicorp/vault
[vault-plugins]: https://www.vaultproject.io/docs/internals/plugins.html
[vault-get-started]: https://www.vaultproject.io/intro/getting-started/install.html
[go]: https://www.golang.org

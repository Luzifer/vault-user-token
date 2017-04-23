# Luzifer / vault-user-token

This project is intended to constantly renew a Vault token derived from a role id.

That way the machine only contains a temporary token expiring after a short while if the program is no longer running. So if a machine is lost (physically) the corresponding secret can be revoked and the machine will no longer be able to access the vault instance.

----

![project status](https://d2o84fseuhwkxk.cloudfront.net/vault-user-token.svg)

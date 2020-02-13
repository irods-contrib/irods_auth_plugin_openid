# irods_auth_plugin_openid

## Summary
This irods auth plugin allows a user to log into iRODS using credentials from an existing OpenID identity.

## Prerequisites:

1. A token management service must be installed.  This service handles the mapping of OpenID identity provider short names (like globus, google, yahoo, cilogon) to the actual API endpoints for those providers, as well as receiving the HTTP callbacks upon user login, exchanging the authorization code for tokens, parsing token responses, safely storing the tokens, and refreshing them when they expire.  The service acts as an abstraction layer on top of all of those operations, for client applications (like this auth plugin) which only want to have a user log in at a provider, and receive the token back when they do.  See the information here (https://github.com/heliumdatacommons/auth_microservice) on how to set it up.
2. The token service is served at a domain accessible by the users who will be logging into iRODS.  If all logins will be done in a private network, then it is okay to serve it at a private host.  The service must also have TLS enabled.  This can be done by binding the service to 127.0.0.1 and then putting an NGINX instance with an SSL cert in front of it as a reverse proxy.
3. An API key is acquired from the token management service.  This is done by calling `/admin/key` on the token service host, with an owner param set to some string identifying the application, and with the `Authorization: Basic <admin.key>` header set.  Example:
```
$ curl -H "Authorization: Basic 55555555" "https://token.example.org/admin/key?owner=irods_server_1"
```
4. The user has an iRODS account.  See iRODS documentation for how to create a user.
5. The iRODS account has an OpenID subject id linked to it.  The subject id is unique per provider, whereas an email is not necessarily.  The following link has information on how to lookup your OpenID identity's subject id (https://github.com/heliumdatacommons/auth_microservice/wiki/API-and-Use).  Once the subject id is known, it can then be added as an auth-name to the iRODS account with `iadmin aua <irods-account> <subject-id>`.  It is critical at this time that an iRODS account only have one auth-name linked to it in this fashion.  However, multiple iRODS accounts can be linked to the same auth-name.  
6. The iRODS server is set up with the following JSON in the plugin_configuration->authentication section. 
```
"openid": {
  "token_service": "https://your-token-management-hostname",
  "token_service_key": "<the-api-key-from-step-3>"
}
```
7. The iRODS client's ~/.irods/irods_environment.json file has their iRODS user set, as well as the following two keys:
```
"irods_authentication_scheme": "openid",
"openid_provider": <the-provider-shortname>
```
8. iRODS v4.2.3 is installed
9. iRODS SSL is configured server-side. This is a strict requirement.  Authentication with an iRODS server over the OpenID scheme will always use SSL/TLS and it will fail if no certificate is configured. (see: [server-ssl-setup](https://docs.irods.org/4.2.3/plugins/pluggable_authentication/#server-ssl-setup))

## Use
Now this plugin can be installed on an iRODS server, and on the client system which will be used to access the iRODS server.

1. Run iinit
2. Browse to the url provided at the command prompt.  This command will hang by default for 60 seconds while waiting for you to log in.
3. Log in at the OpenID identity provider's website using the url.
4. The iinit command will exit.
5. Run any other iRODS client commands, which will now have the permissions of your iRODS account associated with the OpenID account in the pre-requisite steps.

## Further comments

### Interaction with high-availability setups

If you use this plugin in combination with a high-availability irods setup such as 
https://irods.org/2015/07/configuring-irods-for-high-availability/
then you need to ensure that users stay on the same back-end service.
This is strictly only needed during the authentification phase (as a direct network connection is made to submit the nonce),
but it does not hurt setting it globally.

For haproxy, the needed lines are: 
	balance source
	hash-type consistent
in the backend section.


### Interaction with keycloak

Keycloak produces large tokens which do not fit in the iRODS username field. See
https://indico.cern.ch/event/854707/contributions/3681126/
for details.

In this case, tokens should be pre-authorized with the broker service and hashed prior to submission to iRODS.
On the commend line, after iinit is run, the token should be hashed (e.g. by using the example script at
https://github.com/RubenGarcia/python-irodsclient/tree/openid/examples/iinit

If you plan to use the python client, 
https://github.com/RubenGarcia/python-irodsclient
will hash the token automatically if it is larger than 1024 bytes.

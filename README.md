
pyrax-identity-hubic
====================

HubiC identity module for rackspace's pyrax library.

## How to use
    pyrax.set_setting("identity_type", "pyrax_identity_hubic.HubicIdentity")

then in pyrax's credential file, you could do:

    [hubic]
    email = your_email
    password = your_password
    client_id = api_client_id
    client_secret = api_secret_key
    redirect_uri = api_redirect_uri

## duplicity support
TODO...

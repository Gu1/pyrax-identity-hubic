#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import sys
import pyrax

if len(sys.argv) < 6:
    print >>sys.stderr, "Usage:\n  test_pyrax_identity_hubic.py [email] "\
                        "[password] [client_id] [client_secret] [redirect_uri]"
    sys.exit(1)

pyrax.set_setting("identity_type", "pyrax_identity_hubic.HubicIdentity")
pyrax._create_identity()
email, password = sys.argv[1], sys.argv[2]
client_id, client_secret, redirect_uri = sys.argv[3], sys.argv[4], sys.argv[5]
pyrax.identity.set_credentials(email, password, client_id, client_secret,
                               redirect_uri, authenticate=True)
pyrax.connect_to_services(region=None)
cf = pyrax.cloudfiles

for cont_name in cf.list_containers():
    cont = cf.get_container(cont_name)
    print "%s:" % (cont_name,)
    files = cont.get_object_names(full_listing=True)
    if files:
        print '\n'.join(['  - '+f for f in files])
    else:
        print "  <empty>"


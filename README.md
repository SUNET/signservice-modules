[![License](https://img.shields.io/badge/License-BSD_2--Clause-orange.svg)](https://opensource.org/licenses/BSD-2-Clause)

# eduSign Signature Service

---

A packaging of a Signature Service built using DIGG's open source repository https://github.com/swedenconnect/signservice.

## About

This repository contains plugin modules for a SignService to be used in a number of setups relevant for eduSign. These are:

- User authentication using Swamid/NORDUnet federation
- User authentication done by the Harica CA when issuing certificates based on MyAcademic ID authentication

We build the SignService using DIGG:s Open Source packing of a SignService - https://github.com/swedenconnect/signservice.

For documentation of the SignService base, including detailed configuration instructions,
see https://docs.swedenconnect.se/signservice/.

## Configuration

See https://docs.swedenconnect.se/signservice/configuration.html

A good example is to view the [application-sandbox.yml](https://github.com/SUNET/signservice-modules/blob/main/signservice-app/src/main/resources/application-sandbox.yml) which
is a documented configuration file for the test installation of this application.

> Go to https://sig2.idsec.se/sigdemo2/open/login to test it.

The Harica CA setup has its own configuration documentation [here](harica/README.md).


## Building and installing

To build the application and create a Docker image run the `deploy/build.sh` script.

To run the application use a script looking something like:

```
#!/bin/bash

REDIS_PORT=6379
SIGNSERVICE_HTTPS_PORT=9070

if [ "$SIGNSERVICE_DIR" == "" ]; then
  echo "Variable SIGNSERVICE_DIR must be set"
  exit 1
fi

if [ ! -d ${SIGNSERVICE_DIR}/config ]; then
  echo "Directory ${SIGNSERVICE_DIR}/config must exist and contain the SignService configuration"
  exit 1
fi

SS_HOME=/opt/edusign-signservice

echo Starting docker container edusign-signservice ...
docker run -d --name edusign-signservice --restart=always \
  -p ${SIGNSERVICE_HTTPS_PORT}:8443 \
  -e SIGNSERVICE_HOME=${SS_HOME} \
  -e SPRING_CONFIG_LOCATION=${SS_HOME}/config/application.yml \
  -e "TZ=Europe/Stockholm" \
  -v /etc/localtime:/etc/localtime:ro \
  -v ${SIGNSERVICE_DIR}:${SS_HOME} \
  edusign-signservice

echo Done!

```

But before we can do this we need to have an `application.yml` file set up with the configuration settings
for the application. 

> A template `config` directory with an `application.yml` is available (but not posted here).

## Adding Clients and Publishing of SAML metadata

This section is relevant only when user authentication is done using a SAML federation (Swamid/NORDUnet).

The `application.yml` file contains the entire SignService configuration along with one, or more, "engines".
A SignService engine is really a configuration for one client (relying party).

The [Signature Service Configuration documentation](https://docs.swedenconnect.se/signservice/configuration.html) tells in detail how this is done. However, there is a special thing to point out here: 

**Every client must have its own SAML SP configuration!**

This may be hard to understand, but if you think of how a SignService is working you'll understand. When the
end-user signs a document he or she is directed to the Identity Provider for "authentication for signature".
Normally, this Identity Provider, includes information about which relying party that has requested the
authentication. So, if a user logs in to service "Example Company" and is prompted to sign a document
we need to ensure that the SignService SP requesting the user to "authenticate for signature" also states
that it is "Example Company".

The SignService configuration enables you to configure the SAML metadata using just property values, and
you can also include a template XML-file containing some of the metadata stuff that can't be expressed using
property values. 

A SignService will also expose its SAML metadata for all configured clients (engines). The path on which it
does this is also configurable (`engines[number].authn.saml.sp-paths.metadata-publishing-path`). So if we 
have configured the path `/sign/our-client/saml/metadata` we point our browser to 
`https://our-domain/sign/our-client/saml/metadata` and download the metadata.

This metadata must now be published to the metadata registry of the federation that the client is using.

> Note: Should you need to change anything in the metadata, you can always do it manually, as long as
you don't change any certificates or paths.





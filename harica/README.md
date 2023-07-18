# Harica CA authentication plugin

---

The Harica CA authentication plugin allows user authentication to be handled by an external CA based on the Harica API
for requesting certificate issuance.

To use this feature the following configurations must be done:

1) Specify a sign service engine that use the authentication and key and cert modules provided here.
2) Provide configuration data for the Harica based authentication process.

## Architecture

When these plugin modules are used the flow of events in the sign service is altered in the following way:

1) The Sign service receives a sign request on a URL that is configured to use this signature process.
2) The user is prepared for signing using the following steps:
   1) A backend call is sent to the Harica CA to ensure that the user is registered at the CA
   2) A key pair is generated for this instance of signing and a certificate request is generated and sent to the Harica CA
3) The user is transferred to the Harica CA where the following steps are completed:
   1) The user is authenticated using MyAcademic ID
   2) A certificate is issued for the public key in the pre-registered request
   3) The user is returned back to sign service with the issued certificate
4) The certificate returned from the CA is used together with the generated key to complete the signing process.

## Configuration

Configuration is done by updating/amending the application.yml file that is described in the main documentation. There are two main
recommended strategies:

1) By creating a complete new `application.yml` file with suitable settings for this sign service engine
2) By providing the settings specific for using the Harica sign service engine plugins in a separate delta configuration file named
`application-harica.yml` and to activate the use of these additional configuration settings file by specifying the active profile "harica" in the Spring Boot
property settings (`spring.profiles.active`).

The example below shows the content of such delta configuration file that specifies only those settings that are specific for
the use of these plugins.

### Property settings

The following property settings are relevant for activating and using these plugin modules

### Activation

To activate these plugin modules a new engine specification must be provided that invoke the use of these plugin modules.
Here is an example that shows how this is done:

```
signservice:
  domain: localhost:8443
  base-url: https://${signservice.domain}
  default-sign-service-id: https://${signservice.domain}/edusign-harica-signservice
  #
  # Client configuration - Each client has an own "engine".
  #
  engines:
  
    #
    # Name of this engine
    #
  - name: "eduSign-test-harica"
  
    #
    # The processing path(s) for this client. Note that all paths must begin with /sign
    #
    processing-paths:
    - /sign/esharica/signrequest
    
    #
    # Client name and certificate(s). This is the certificate(s) used to sign SignRequest messages.
    #
    client:
      client-id: https://eid2cssp.3xasecurity.com/sign
      trusted-certificates:
      - ${cfgdir}/clients/selftest-sp/sp.crt

    #
    # Specifying use of the Harica CA Authentication handler
    #
    authn:
        external:
            bean-name: signservice.HaricaCAAuthenticationHandler

    cert:
        external:
            bean-name: signservice.HaricaCAKeyAndCertificateHandler

    audit:
      file:
        name: "signservice-test-app-audit"
        file-name: ${SIGNSERVICE_HOME}/audit/eduSign-test-idsec/audit.log
```

### Harica CA Authentication Configuration

The Harica CA authentication configuration is provided by the following property settings using the prefix "`harica-authn"`:

| Property                          | Description                                                         | Presence  |
|-----------------------------------|---------------------------------------------------------------------|-----------|
| connect-timeout                   | HTTP connect timeout in milliseconds                                | Mandatory |
| read-timeout                      | HTTP read timeout in milliseconds                                   | Mandatory |
| request-signing-credential        | Credentials for signing requests to the CA                          | Mandatory |
| request-signing-algorithm         | JWSAlgorithm name used to sign request to CA                        | Mandatory |
| trusted-ca-token-verification-key | Trusted public key for validating certificate result tokens from CA | Mandatory |
| http-proxy                        | Http Proxy configuration data                                       | Optional  |
| sp-url                            | SP url configuration                                                | Mandatory |
| ca                                | CA configuration parameters used by the handler                     | Mandatory |

#### CA Configuration

The following property settings are used to configure the Harica CA authentication handler operations

| Property                    | Description                                                                                                                               | Presence  |
|-----------------------------|-------------------------------------------------------------------------------------------------------------------------------------------|-----------|
| get-user-url                | The URL at the CA receiving request to get information about a registered user                                                            | Mandatory |
| register-user-url           | The URL at the CA receiving request to register new users at the CA                                                                       | Mandatory |
| register-csr-url            | The URL at the CA receiving request to register a CSR for a new certificate request                                                       | Mandatory |
| certificate-issuance-url    | The URL the user is redirected to at the CA in order to complete authentication and issue a certificate based on the registered CSR       | Mandatory |
| allow-new-user-registration | Set to true to allow new user registration at the CA if the requested user attribute contains sufficient data about the user              | Mandatory |
| key-gen-type                | The key type being generated for the user at each instant of signing                                                                      | Mandatory |
| cert-req-algo               | The algorithm used to sign the CSR with the user generated key                                                                            | Mandatory |
| ca-certificate-chain        | The list of certificate resources (including the root) used by the CA that issues the certificate for the user                            | Mandatory |
| loa                         | Level of assurance assigned to assertion objects based on this authentication process (to be compared with the sign request requirements) | Mandatory |

#### SP URL Configuration
The following property settings are used to specify SP URL configurations

| Property                | Description                                                                                                             | Presence  |
|-------------------------|-------------------------------------------------------------------------------------------------------------------------|-----------|
| base-url                | The base URL used by the sign service                                                                                   | Mandatory |
| certificate-return-path | The path added to the base-url to form the URL used to return the user back to sign service with the issued certificate | Mandatory |

#### Request Signing Credential

The following property settings are used to specify credentials used to sign request data to the Harica CA

| Property       | Description                                                                                                  | Presence  |
|----------------|--------------------------------------------------------------------------------------------------------------|-----------|
| ec-private-key | Base64 encoded elliptic curve (EC) private key in raw binary format or in PKCS8 format (Must be a P-256 key) | Mandatory |
| ec-public-key  | The corresponding public key  as Base64 binary data                                                          | Optional  |

#### HTTP Proxy Configuration

The following property settings are used to specify SP Proxy configurations. Proxy configuration is optional but if present the
individual parameters must be present according to this table:

| Property  | Description    | Presence  |
|-----------|----------------|-----------|
| host      | The proxy host | Mandatory |
| port      | The proxy port | Mandatory |
| user-name | User name      | Optional  |
| password  | Password       | Optional  |


### Example

This example shows a valid Harica CA authentication configuration:

```
harica-authn:
  connect-timeout: 2000
  read-timeout: 5000
  request-signing-credential:
    ec-private-key: ${cfgdir}/ca/harica/req-signer-private
    ec-public-key: ${cfgdir}/ca/harica/req-signer-public    
  request-signing-algorithm: ES256
  trusted-ca-token-verification-key: ${cfgdir}/ca/harica/ca-token-key.pem  
  sp-url:
    base-url: https://localhost:8443
    certificate-return-path: /sign/cert-return
    
  ca:
    get-user-url: https://cm-stg.harica.gr/api/CrossOrigin/GetEdusignUser
    register-user-url: https://cm-stg.harica.gr/api/CrossOrigin/CreateEdusignUser
    register-csr-url: https://cm-stg.harica.gr/api/CrossOrigin/RequestEdusignCertificate
    certificate-issuance-url: https://cm-stg.harica.gr/Welcome
    allow-new-user-registration: false
    key-gen-type: EC-256
    cert-req-algo: http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256
    ca-certificate-chain:
      - ${cfgdir}/ca/harica/ca-cert.crt
      - ${cfgdir}/ca/harica/root-cert.crt
    loa: http://id.elegnamnden.se/loa/1.0/eidas-nf-sub
    
```


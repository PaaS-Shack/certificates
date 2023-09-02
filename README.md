# Certificates

Here are short descriptions of the three services: `v1.certificates`, `v1.certificates.account-keys`, and `v1.certificates.acme`:

1. **`v1.certificates` Service:**
   - This service is responsible for managing SSL/TLS certificates.
   - It can create, retrieve, and update certificates, supporting both Let's Encrypt and self-signed certificates.
   - It provides actions for listing expiring certificates, requesting certificates, and resolving domains to certificates.
   - The service also offers detailed information about certificates, including issuer and subject details.
   - Overall, `v1.certificates` handles the lifecycle and management of SSL/TLS certificates for domains.

2. **`v1.certificates.account-keys` Service:**
   - This service manages account keys for Let's Encrypt and other ACME (Automated Certificate Management Environment) providers.
   - It allows users to create account keys associated with email addresses.
   - Account keys are used for certificate issuance and management.
   - The service ensures that account keys are unique based on email, environment, and provider.
   - It interacts with ACME libraries and the database to handle account key operations efficiently.

3. **`v1.certificates.acme` Service:**
   - This service integrates with the ACME (Automated Certificate Management Environment) protocol for certificate management.
   - It interacts with ACME providers, such as Let's Encrypt, to obtain SSL/TLS certificates.
   - The service supports domain validation methods like DNS-01 and HTTP-01 to prove domain ownership.
   - It automates the process of certificate issuance and renewal, making it easier to secure domains with SSL/TLS certificates.
   - The `v1.certificates.acme` service simplifies the interaction with ACME providers and abstracts the underlying complexity of certificate management.

These services collectively provide the infrastructure for managing certificates, account keys, and interactions with ACME providers to secure web applications and services with SSL/TLS encryption.


# Certificates Service Documentation

The Certificates service is responsible for managing certificates, including Let's Encrypt and self-signed certificates. This documentation provides an overview of the service's actions, parameters, and usage examples.

## Actions

### 1. create

Create a new certificate.

**Parameters:**
- `privkey` (String): Private key for the certificate.
- `chain` (String): Certificate chain.
- `cert` (String): Certificate.
- `domain` (String): Domain associated with the certificate.
- `email` (String): Email address associated with the certificate.
- `owner` (String): Owner of the certificate (optional).
- `environment` (String): The environment for the certificate (production or staging).
- `type` (String): The type of certificate (selfsigned or letsencrypt).
- `expiresAt` (Number): Expiration timestamp of the certificate (optional).

**Usage:**

```json
POST /v1/certificates/create

{
  "privkey": "-----BEGIN PRIVATE KEY----- ...",
  "chain": "-----BEGIN CERTIFICATE----- ...",
  "cert": "-----BEGIN CERTIFICATE----- ...",
  "domain": "example.com",
  "email": "admin@example.com",
  "environment": "staging",
  "type": "letsencrypt"
}
```

### 2. getExpiring

Get a list of expiring certificates that are older than 60 days.

**Usage:**

```json
GET /v1/certificates/getExpiring
```

### 3. listExpiring

Get a list of certificates that are older than 60 days.

**Usage:**

```json
GET /v1/certificates/listExpiring
```

### 4. requestCert

Request a certificate for a domain using Let's Encrypt. This action points to the Let's Encrypt DNS action for certificate issuance.

**Parameters:**
- `domain` (String): Domain for which the certificate is requested.
- `environment` (Enum): The environment for the certificate (production or staging, optional).

**Usage:**

```json
POST /v1/certificates/requestCert

{
  "domain": "example.com",
  "environment": "staging"
}
```

### 5. updateExpiring

Update expiring certificates with new ones.

**Usage:**

```json
POST /v1/certificates/updateExpiring
```

### 6. resolveDomain

Resolve a domain to a certificate or create one if it doesn't exist.

**Parameters:**
- `domain` (String): Domain for which the certificate is resolved or created.
- `environment` (Enum): The environment for the certificate (production or staging, optional).
- `type` (Enum): The type of certificate (selfsigned or letsencrypt, optional).

**Usage:**

```json
POST /v1/certificates/resolveDomain

{
  "domain": "example.com",
  "environment": "staging",
  "type": "letsencrypt"
}
```

### 7. details

Get detailed information about a certificate.

**Parameters:**
- `id` (String): Certificate ID.

**Usage:**

```json
GET /v1/certificates/details?id=certificateId
```

## Permissions

Ensure that appropriate permissions are set to use these actions, such as creating and retrieving certificates.

## Response

The service returns JSON responses containing details of certificates, such as private key (`privkey`), certificate chain (`chain`), certificate (`cert`), domain, email, owner, environment, type, and expiration timestamp (`expiresAt`).

For detailed certificate information returned by the `details` action, the response includes the issuer, subject, validity, serial number, and extensions.

## Error Handling

- If a certificate with the specified domain, environment, and type already exists, a `409` conflict error is thrown.
- If a certificate is not found for the specified parameters in the `resolveDomain` action, a new certificate is created based on the type specified.
- If the certificate type is not recognized in the `resolveDomain` action, a `400` bad request error is thrown.

## Additional Information

- The service supports both Let's Encrypt and self-signed certificates.
- The `getExpiring` and `listExpiring` actions provide lists of certificates that are older than 60 days.
- The `requestCert` action initiates Let's Encrypt certificate issuance using the DNS challenge.
- The `updateExpiring` action updates expiring certificates with new ones.
- The `resolveDomain` action resolves domains to certificates or creates new ones as needed.
- The `details` action provides detailed information about a certificate, including issuer, subject, and more.

For more in-depth information and advanced usage, refer to the service's source code and related documentation.

# Certificates ACME Service Documentation

The Certificates ACME service provides certificate management capabilities using the ACME protocol, supporting both Let's Encrypt and self-signed certificates. This documentation outlines the service's actions, their parameters, and provides usage examples.

## Actions

### 1. letsencrypt

Request a new certificate from Let's Encrypt and save it to the certificates service.

**Parameters:**
- `domain` (String): Domain name for which to obtain the certificate (Fully Qualified Domain Name).
- `environment` (Enum): The environment for certificate issuance (production or staging).

**Usage:**

```json
POST /v1/certificates/acme/letsencrypt

{
  "domain": "example.com",
  "environment": "production"
}
```

### 2. selfsigned

Generate a new self-signed certificate and save it to the certificates service.

**Parameters:**
- `domain` (String): Domain name for which to generate the self-signed certificate (Fully Qualified Domain Name).
- `environment` (Enum): The environment for certificate issuance (production or staging).

**Usage:**

```json
POST /v1/certificates/acme/selfsigned

{
  "domain": "example.com",
  "environment": "staging"
}
```

### 3. revoke

Revoke an existing certificate.

**Parameters:**
- `id` (String): Certificate ID to revoke.

**Usage:**

```json
POST /v1/certificates/acme/revoke

{
  "id": "certificate_id_here"
}
```

### 4. renew

Renew an existing certificate.

**Parameters:**
- `id` (String): Certificate ID to renew.

**Usage:**

```json
POST /v1/certificates/acme/renew

{
  "id": "certificate_id_here"
}
```

## Permissions

To use these actions, ensure that appropriate permissions are granted. For example:
- `certificates.acme.letsencrypt`
- `certificates.acme.selfsigned`
- `certificates.acme.revoke`
- `certificates.acme.renew`

## Response

The service returns a JSON response containing details about the certificate, including the certificate type, cert, privkey, chain, and expiration date.

```json
{
  "domain": "example.com",
  "email": "admin@example.com",
  "environment": "production",
  "type": "letsencrypt",
  "cert": "-----BEGIN CERTIFICATE----- ...",
  "privkey": "-----BEGIN PRIVATE KEY----- ...",
  "chain": "-----BEGIN CERTIFICATE----- ...",
  "expiresAt": "2024-09-01T00:00:00.000Z"
}
```

## Error Handling

- If a domain is not found, a `404` error with the message "Domain not found" is thrown.
- If a certificate is not found, a `404` error with the message "Certificate not found" is thrown.

## Additional Information

- This service uses the ACME protocol for Let's Encrypt certificate issuance.
- Self-signed certificates are generated with specific settings.
- DNS challenges are used for domain validation when obtaining Let's Encrypt certificates.

For more detailed information and advanced usage, refer to the service's source code and Moleculer framework documentation.

# Certificates Account Keys Service Documentation

The Certificates Account Keys service is responsible for managing ACME account keys, particularly for Let's Encrypt and other ACME providers. This documentation provides an overview of the service's actions, parameters, and usage examples.

## Actions

### 1. createPrivateKey

Create a new account key for a given email address. This key will be used to create new certificates. The account key is saved to the database.

**Parameters:**
- `email` (String): Email address associated with the account key.
- `environment` (Enum): The environment for the account key (production or staging).
- `provider` (Enum): The ACME provider (currently supports "letsencrypt").

**Usage:**

```json
POST /v1/certificates/account-keys/createPrivateKey

{
  "email": "admin@example.com",
  "environment": "staging",
  "provider": "letsencrypt"
}
```

### 2. getPrivateKey

Retrieve the account key for a given email address, environment, and provider.

**Parameters:**
- `email` (String): Email address associated with the account key.
- `environment` (Enum): The environment for the account key (production or staging).
- `provider` (Enum): The ACME provider (currently supports "letsencrypt").

**Usage:**

```json
GET /v1/certificates/account-keys/getPrivateKey?email=admin@example.com&environment=production&provider=letsencrypt
```

## Permissions

Ensure that appropriate permissions are set to use these actions, such as creating and retrieving account keys.

## Response

The service returns a JSON response containing details of the account key, including the private key (`privkey`), certificate chain (`chain`), certificate (`cert`), environment, provider, and email.

```json
{
  "privkey": "-----BEGIN PRIVATE KEY----- ...",
  "chain": "-----BEGIN CERTIFICATE----- ...",
  "cert": "-----BEGIN CERTIFICATE----- ...",
  "environment": "production",
  "provider": "letsencrypt",
  "email": "admin@example.com"
}
```

## Error Handling

- If an account key already exists for the specified email, environment, and provider, a `409` conflict error is thrown.
- If no account key is found for the specified email, environment, and provider, a `404` not found error is thrown.

## Additional Information

- The service uses the ACME protocol to create and manage account keys.
- Account keys are associated with email addresses and used for certificate issuance.

For more in-depth information and advanced usage, refer to the service's source code and related documentation.
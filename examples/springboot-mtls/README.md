# Spring Boot 3.2+ Mutual TLS (mTLS) Example with `mgtls`

This example demonstrates how to configure a **Spring Boot 3.2+** REST API server and `RestClient` with **native PEM SSL Bundles** (`spring.ssl.bundle.pem`) and strict Mutual TLS (`server.ssl.client-auth: need`) provisioned by `mgtls`.

Because Spring Boot 3.1+ supports PEM files directly without requiring legacy Java JKS keystores, `mgtls` outputs (`fullchain.pem`, `key.pem`, `ca-chain.pem`) drop directly into `application.yml`. For legacy JVM integrations, `mgtls` also generates a PKCS#12 (`bundle.p12`) file automatically.

## Files in This Example

| File | Description |
| :--- | :--- |
| [`application.yml`](file:///home/bill/src/sysadmin/mgtls/examples/springboot-mtls/application.yml) | Spring Boot 3.2+ configuration defining `mtls-server` and `mtls-client` PEM SSL bundles with `keystore`, `truststore`, TLS 1.3 protocol enforcement, and `client-auth: need`. |
| [`MtlsController.java`](file:///home/bill/src/sysadmin/mgtls/examples/springboot-mtls/MtlsController.java) | Spring `@RestController` and `@Configuration` class exposing `/api/v1/mtls/whoami` (extracting the peer `X509Certificate` chain and Spring Security principal) and a pre-configured mTLS `RestClient` bean. |
| [`setup_springboot_mtls.sh`](file:///home/bill/src/sysadmin/mgtls/examples/springboot-mtls/setup_springboot_mtls.sh) | Script that runs `mgtls` to provision the Root CA, Intermediate CA, Spring Boot Server & Client certificates, and the `springboot` target bundle. |

## Quickstart

### 1. Generate Certificates and Target Bundle

```bash
./setup_springboot_mtls.sh
```

### 2. Run Spring Boot with the Generated Profile

```bash
./mvnw spring-boot:run -Dspring-boot.run.arguments="--spring.config.additional-location=file:./application.yml"
```

### 3. Verify Mutual TLS with `curl`

```bash
curl --silent --show-error --fail \
  --cacert .mgtls-springboot/certs/springboot-srv/ca-chain.pem \
  --cert .mgtls-springboot/certs/springboot-client/cert.pem \
  --key .mgtls-springboot/certs/springboot-client/key.pem \
  https://localhost:8443/api/v1/mtls/whoami | jq .
```

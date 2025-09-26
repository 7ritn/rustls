<p align="center">
  <img width="460" height="300" src="https://raw.githubusercontent.com/rustls/rustls/main/admin/rustls-logo-web.png">
</p>

<p align="center">
Rustls is a modern TLS library written in Rust.
</p>

# About this fork

Rustls is a modern TLS library fully written in Rust. This fork adds FIDO2-based client authentication to rustls. For this both the server and client code was modified.
The client uses the authenticator library to communicate with USB-attached FIDO2 tokens. The server can both register and authenticate clients. For registration a double handshake is required.
Token response is validated with webauthn-rs. All the FIDO2 specific code is outsourced into the rustls-fido library.

## FIDO2 Server example program

This server can accept FIDO2 client authentication. For this a fido.db3 SQLite database file will be created in the current directory. All configuration parameters can be specified using environment variables. 

| Variable Name                   | Description                            | Default Value                 | Example Value                     |
|---------------------------------|----------------------------------------|-------------------------------|-----------------------------------|
| `CA_CERT_PATH`                  | Path to the CA certificate file        | `./tls-certs/ca.cert.pem`     | `/etc/ssl/certs/ca.cert.pem`      |
| `SERVER_CERT_PATH`              | Path to the server certificate file    | `./tls-certs/server.cert.pem` | `/etc/ssl/certs/server.cert.pem`  |
| `SERVER_KEY_PATH`               | Path to the server private key file    | `./tls-certs/server.key.pem`  | `/etc/ssl/private/server.key.pem` |
| `SERVER_ADDRESS`                | Address and port to bind the server to | `[::]:4443`                   | `example.com:443`                 |
| `FIDO_RP_ID`                    | FIDO Relying Party ID                  | `localhost`                   | `example.com`                     |
| `FIDO_RP_NAME`                  | FIDO Relying Party Name                | `localhost`                   | `Example Inc.`                    |
| `FIDO_USER_VERIFICATION`        | FIDO user verification policy          | `Preferred`                   | `Required`                        |
| `FIDO_AUTHENTICATOR_ATTACHMENT` | FIDO authenticator attachment          | `CrossPlatform`               | `Platform`                        |
| `FIDO_TIMEOUT`                  | FIDO timeout in milliseconds           | `60000`                       | `30000`                           |
| `FIDO_TICKET`                   | FIDO ticket as comma-separated bytes   | `4,3,2,1`                     | `1,2,3,4`                         |
| `FIDO_MANDATORY`                | Make FIDO authentication mandatory     | `true`                        | `false`                           |
| `FIDO_DB_PATH`                  | Path to the FIDO database file         | `./fido.db3`                  | `/var/lib/fido.db3`               |


```
cargo run --package rustls-examples --bin fidoserver
```

## FIDO2 Client example program

This client can both register and authenticate a USB FIDO2 token with the server. All configuration parameters can be specified using environment variables.
The FIDO mode can also be specified using the command line with the `--authenticate` and `--register` flags.

| Variable Name      | Description                                   | Default Value                 | Example Value                     |
|--------------------|-----------------------------------------------|-------------------------------|-----------------------------------|
| `CA_CERT_PATH`     | Path to the CA certificate file               | `./tls-certs/ca.cert.pem`     | `/etc/ssl/certs/ca.cert.pem`      |
| `CLIENT_CERT_PATH` | Path to the client certificate file           | `./tls-certs/client.cert.pem` | `/etc/ssl/certs/client.cert.pem`  |
| `CLIENT_KEY_PATH`  | Path to the client private key file           | `./tls-certs/client.key.pem`  | `/etc/ssl/private/client.key.pem` |
| `SERVER_ADDRESS`   | Address and port of the server to connect to  | `localhost:4443`              | `example.com:443`                 |
| `SERVER_NAME`      | Server name for TLS SNI                       | `localhost`                   | `example.com`                     |
| `FIDO_MODE`        | FIDO mode: "registration" or "authentication" | `registration`                | `authentication`                  |
| `FIDO_USERNAME`    | FIDO username for authentication/registration | `user`                        | `alice`                           |
| `FIDO_DISPLAYNAME` | FIDO display name                             | `user`                        | `Alice Smith`                     |
| `FIDO_PIN`         | FIDO PIN for authentication                   | `1234`                        | `5678`                            |
| `FIDO_TICKET`      | FIDO ticket as comma-separated bytes          | `4,3,2,1`                     | `1,2,3,4`                         |


To run the client:

```sh
cargo run --package rustls-examples --bin fidoclient
```

# License

Rustls is distributed under the following three licenses:

- Apache License version 2.0.
- MIT license.
- ISC license.

These are included as LICENSE-APACHE, LICENSE-MIT and LICENSE-ISC
respectively.  You may use this software under the terms of any
of these licenses, at your option.
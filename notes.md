# Handshake Messages

## Client Hello
Client Connection
 ->
new_with_alpn (allows specification of extra extensions)
    - should be able to move extra extensions outside when configuring client
 ->
start_handshake
 ->
Main function for sending the message is: emit_client_hello_for_retry(hs.rs)
    - collects extensions send to server
 ->
Handshake Message Payload encoded with ClientHelloPayload, where the different extensions are encoded using the codec

## Sending Certificate Request
- Server emits cert request in emit_certificate_req_tls13 in server/tls13.rs (699)
    - CertificateRequestPayloadTls13 even has an empty extension field
- Client handles in  ExpectCertificateRequest in client/tls13.rs (842) the cert request
    - Extensions hardcoded in payload structure CertificateRequestPayloadTls13

## Sending Client Cerificate
- Client certificate is sent in emit_certificate_tls13 and emit_certverify_tls13 (1238), would need to modify that (CertificatePayloadTls13)

Modified CertificateRequest message to send some data through a new extension
Client Certificate message does not have any space for extensions at all

Managed to add FIDO state to client and server config and retain FIDO challenge for both client and server
## Project details

Steps for this project:
1.Implement a client to verify Server’s certificate.
2.Exploit information leak vulnerability to retrieve CA’s private key
3.Generate a certificate for your student ID signed by CA’s private key
4.Follow the protocol and send the certificate to the Server

```
#openssl x509 -req -days 3650 -sha1 -extfile /etc/ssl/openssl.cnf 
-extensions v3_req -CA <CA’s certificate> -CAkey <CA’s key> 
-CAserial rootca.srl -CAcreateserial -in <certificate request file> 
-out < Student ID >.crt
```


Simple tool for signing Android APKs, written in Nim for the Dali project.


Signing uses PEM formatted keys, convert your PKCS#8 key to PEM with

```
openssl pkcs8 -inform DER -nocrypt -in test.pk8 > test.key.pem
``` 

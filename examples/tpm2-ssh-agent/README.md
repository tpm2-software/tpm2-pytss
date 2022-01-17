# tpm2-ssh-agent

This example implements (parts of) the SSH agent protocol allowing the usage of tpm2-tss-engine / tpm2-openssl keys for SSH authorization and host keys.
To use the agent you need to generate compatible keys using `tpm2tss-genkey`, `openssl genpkey -provider tpm2` or with the following python code:
```python
from tpm2_pytss.ESAPI import ESAPI
from tpm2_pytss.tsskey import TSSPrivKey

with ESAPI() as ectx:
    key = TSSPrivKey.create_ecc(ectx)
    pemdata = key.to_pem()
    with open("my-tss-key.pem", "wb") as kf:
        kf.write(pemdata)
```

With one or more keys run `tpm2-ssh-agent --socket /tmp/tpm2-ssh-agent.socket my-tss-key.pem`
By setting `$SSH_AUTH_SOCK` to `/tmp/tpm2-ssh-agent.socket` will use the agent, for example:
```console
$ SSH_AUTH_SOCK=/tmp/tpm2-ssh-agent.socket  ssh-add -L
ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPFsmwDzhbBheoDsfbf8VtFWXSeNivNJpeAKR6hYJvihi7jTuQG90/fRKw3yB6Ff2c4Sm3XgYAnExyMeDWUN0lk=
```

# tpm2-pytss examples

The sub directories here contains example usage of the different APIs in action.

* [tpm2_filternv](tpm2_filternv) is a simple tool to display NV areas which matches a set of attributes. \
  Covers usage of ESAPI, TCTILdr and string handling of constants.
* [tpm2-ssh-agent](tpm2-ssh-agent) is a ssh-agent using [tpm2-tss-engine](https://github.com/tpm2-software/tpm2-tss-engine) / [tpm2-openssl keys](https://github.com/tpm2-software/tpm2-openssl) keys. \
  Covers TSSPrivKey and signing using ESAPI.

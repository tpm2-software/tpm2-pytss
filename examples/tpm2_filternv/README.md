# tpm2_nvfilter

Display a list of NV indices which matches zero or more attributes, such as `written` or `authread`.
```console
$ tpm2_nvfilter --filter "platformcreate|policy_delete|writelocked"
0x1800001:
  name: 000b70f1fe7cb8045d9ff1ef39fc64cf247cecad6e1864fb586badab244cac7dfd6a
  hash algorithm:
    friendly: sha256
    value: 0xb
  attributes:
    friendly: authwrite|policy_delete|writelocked|writedefine|authread|noda|written|platformcreate
    value: 0x62042c04
  size: 70
  authorization policy: 1169A46A813A8CCDD0F3066785207BB9B67AFD3A6CD6DFE5C5AEE120867A96DF

```

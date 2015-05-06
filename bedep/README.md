#Bedep Malware Tools
Tools that may assist in analysis of the Bedep malware.

##Usage tips
If you are passing binary data as an argument from the command line you can use the print command to convert escaped hex characters.

```
python bedep_string_decrypt.py "`printf "\xac\xd6\x42\xce\xed\xf7\xe2\x83\x7b\x12\xfb"`"
```

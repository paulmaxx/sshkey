##Intro

OpenSSH Public Key Format Decoders allows you to read a public ssh key.  When decoding a key it performs validation and
so it is very handy for validation use cases.

##Usage

    OpenSSHPublicKeyFormatDecoder decoder = new OpenSSHPublicKeyFormatDecoder("ssh-rsa AAAAB...");

# nanvault

[![Build Status](https://travis-ci.org/marcobellaccini/nanvault.svg?branch=master)](https://travis-ci.org/marcobellaccini/nanvault)
[![GitHub release](https://img.shields.io/github/release/marcobellaccini/nanvault.svg)](https://github.com/marcobellaccini/nanvault/releases)

**nanvault** is not-ansible-vault.

It is a standalone, CLI tool to encrypt and decrypt files in the [Ansible Vault](https://docs.ansible.com/ansible/latest/user_guide/vault.html) format.

**Powerful**: *has UNIX-style composability - you can play with [pipes](https://en.wikipedia.org/wiki/Pipeline_(Unix))!*

**Smart**: *it guesses what you want to do, based on piped input.*

**Batteries-included**: *it features a safe password generator.*

## Installation

You can download the latest binaries from the [releases page](https://github.com/marcobellaccini/nanvault/releases).

## Usage

Generate a *vault password file*, then encrypt and decrypt files:
```
$ nanvault -g > passfile
$ cat test.txt | nanvault -p passfile > test.enc
$ cat test.enc | nanvault -p passfile > decrypted_test.txt

```

Of course, you can provide your own *ansible-vault password files*.

If the *NANVAULT_PASSFILE* environment variable is set, the *vault password file* option may be omitted:
```
$ export NANVAULT_PASSFILE="passfile"
$ nanvault -g > $NANVAULT_PASSFILE
$ echo "Encrypt this! ^_^ " | nanvault
$ANSIBLE_VAULT;1.1;AES256
643439633661336237356434383036353...

```

You can also convert data to and from YAML (this is compatible with [*ansible-vault encrypt_string*](https://docs.ansible.com/ansible/latest/user_guide/vault.html#use-encrypt-string-to-create-encrypted-variables-to-embed-in-yaml)):
```
$ echo "Encrypt this! ^_^ " | nanvault | nanvault -y mystuff
mystuff: !vault |
  $ANSIBLE_VAULT;1.1;AES256
  653936313063303031376236373231336...
$ echo "Encrypt this! ^_^ " | nanvault | nanvault -y mystuff > my.yml
$ cat my.yml | nanvault -Y
$ANSIBLE_VAULT;1.1;AES256
6534346535376538306330623363653...
$ cat my.yml | nanvault -Y | nanvault
Encrypt this! ^_^
```


Get help and discover all the options:
```
$ nanvault -h

```

## Development

**nanvault** is proudly programmed in [Crystal](https://crystal-lang.org/).

*<<Fast as C, Slick as Ruby>>*

## Contributing

1. Fork it (<https://github.com/marcobellaccini/nanvault/fork>)
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request

## Contributors

- [Marco Bellaccini](https://github.com/marcobellaccini) - creator and maintainer

# nanvault

[![Build Status](https://travis-ci.org/marcobellaccini/nanvault.svg?branch=master)](https://travis-ci.org/marcobellaccini/nanvault)
[![GitHub release](https://img.shields.io/github/release/marcobellaccini/nanvault.svg)](https://github.com/marcobellaccini/nanvault/releases)

**nanvault** is not-ansible-vault.

It is a standalone, CLI tool to encrypt and decrypt files in the [Ansible Vault](https://docs.ansible.com/ansible/latest/user_guide/vault.html) format.

**Simple**: *very few options.*

**Powerful**: *has UNIX-style composability - you can play with [pipes](https://en.wikipedia.org/wiki/Pipeline_(Unix))!*

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

```

Get help and discover other options:
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

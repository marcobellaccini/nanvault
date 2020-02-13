# nanvault

[![Build Status](https://travis-ci.org/marcobellaccini/nanvault.svg?branch=master)](https://travis-ci.org/marcobellaccini/nanvault)
[![GitHub release](https://img.shields.io/github/release/marcobellaccini/nanvault.svg)](https://github.com/marcobellaccini/nanvault/releases)

**nanvault** is not-ansible-vault.

It is a standalone, CLI tool to encrypt and decrypt files in the [Ansible Vault](https://docs.ansible.com/ansible/latest/user_guide/vault.html) format.

**It is Simple**: *very few options*.

**It is Powerful**: *has UNIX-style composability - it plays with [pipes](https://en.wikipedia.org/wiki/Pipeline_(Unix))!*.

## Installation

You can download the latest binaries from the [releases page](https://github.com/marcobellaccini/nanvault/releases).

## Usage

Encrypt and decrypt with a *vault password file*:
```
$ cat test.txt | nanvault -p passfile > test.enc
$ cat test.enc | nanvault -p passfile > decrypted_test.txt

```

If the *NANVAULT_PASSFILE* environment variable is set, the *vault password file* option may be omitted:
```
$ export NANVAULT_PASSFILE="passfile"
$ cat test.txt | nanvault > test.enc

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

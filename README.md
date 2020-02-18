# nanvault

[![Build Status](https://travis-ci.org/marcobellaccini/nanvault.svg?branch=master)](https://travis-ci.org/marcobellaccini/nanvault)
[![GitHub release](https://img.shields.io/github/release/marcobellaccini/nanvault.svg)](https://github.com/marcobellaccini/nanvault/releases)

**nanvault** is not-ansible-vault.

It is a standalone CLI tool to encrypt and decrypt files in the [Ansible® Vault](https://docs.ansible.com/ansible/latest/user_guide/vault.html) format.

**Powerful**: *has UNIX-style composability - you can play with [pipes](https://en.wikipedia.org/wiki/Pipeline_(Unix))!*

**Smart**: *it guesses what you want to do, based on piped input.*

**Batteries-included**: *it features a safe password generator and a YAML-string mode.*

**Thoroughly-tested**: *at the time of writing, there are more lines of code devoted to tests than to the program itself.*

**Free and open-source**: *released under the MIT license.*

## Installation

### GNU/Linux

You can download the latest binaries from the [releases page](https://github.com/marcobellaccini/nanvault/releases).

Then, you may want to copy them in some handy path (e.g.: */usr/bin*, */usr/local/bin*).

### macOS

At this moment, there are no precompiled binaries for you (the author is not a macOS user).

However:
- you can [build the program from the sources](#Building-from-sources) (it's easier than you might expect!)
- ...and, if you feel like it, you can contribute to the project with your macOS skills

### Windows

Until the [Crystal Windows porting](https://github.com/crystal-lang/crystal/wiki/Porting-to-Windows) is completed,
you can go with [Windows Subsystem for Linux](https://docs.microsoft.com/en-us/windows/wsl/install-win10).

### From sources

If you prefer, you can [build the program straight from the sources](#Building-from-sources).

## Usage

Generate a *vault password file*, then encrypt and decrypt files:
```
$ nanvault -g > passfile
$ echo "coolstuff" > test.txt
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

If you want to provide a vault-id label, just use the right option:
```
$ echo "Encrypt this! ^_^ " | nanvault -l mylabel
$ANSIBLE_VAULT;1.2;AES256;mylabel
623466656431303538633462666133333935...
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

### Building from sources

1. [Install Crystal](https://crystal-lang.org/install/).
**Please make sure to install *libssl-dev* and *libyaml-dev* too.**
2. Clone this repo (`git clone https://github.com/marcobellaccini/nanvault`)
3. Build with *shards* (`shards build`)

Instead, if you have Docker, you can compile a statically-linked binary (using
the official Crystal Alpine-Linux Docker images) by running the build script:
```
./build.sh [debug/release]
```

## Contributing

1. Fork it (<https://github.com/marcobellaccini/nanvault/fork>)
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request

## Contributors

- [Marco Bellaccini](https://github.com/marcobellaccini) - creator and maintainer

---

Ansible® is a registered trademark of Red Hat, Inc. in the United States and other countries.

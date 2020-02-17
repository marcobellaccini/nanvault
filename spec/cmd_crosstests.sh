#!/bin/bash
#
# Simple script to perform command line program and cross-tools tests
#
TEST_WORKDIR="tmp_crosstests"
VAULTPASS_FILE="${TEST_WORKDIR}/vaultpassfile"
PLAINTEXT_FILE="${TEST_WORKDIR}/plaintext"
WORK_FILE="${TEST_WORKDIR}/work"
OUT_FILE="${TEST_WORKDIR}/outfile"

NANVAULT="./bin/nanvault"

# cleanup function
cleanup ()
{
    rm -r $TEST_WORKDIR
}

# exiterror function
exiterror ()
{
    cleanup
    exit 1;
}

# checkfiles function
checkfiles ()
{
    diff $PLAINTEXT_FILE $OUT_FILE
    if [ "$?" -ne "0" ]
    then
        echo "CROSS-TESTS FAILED."
        exiterror
    fi
    # delete outfile
    rm $OUT_FILE
    # refresh workfile
    cp $PLAINTEXT_FILE $WORK_FILE
}

# create tests workdir
mkdir $TEST_WORKDIR

# generate vault password file and plaintext file
$NANVAULT -g > $VAULTPASS_FILE
echo -n "test plaintext" > $PLAINTEXT_FILE

# check password file length
PAS_SIZE=$(wc -m < "$VAULTPASS_FILE")
if [ "$PAS_SIZE" -ne "20" ]
    then
        echo "PASSWORD FILE GENERATION FAILED."
        exiterror
fi

# generate workfile
cp $PLAINTEXT_FILE $WORK_FILE

## NO LABEL

# encrypt with nanvault, decrypt with nanvault
cat $WORK_FILE | $NANVAULT -p $VAULTPASS_FILE | $NANVAULT -p $VAULTPASS_FILE > $OUT_FILE
checkfiles

# encrypt with nanvault, decrypt with ansible-vault
cat $WORK_FILE | $NANVAULT -p $VAULTPASS_FILE > $OUT_FILE
ansible-vault decrypt --vault-password-file $VAULTPASS_FILE $OUT_FILE
checkfiles

# encrypt with ansible-vault, decrypt with nanvault
ansible-vault encrypt --vault-password-file $VAULTPASS_FILE $WORK_FILE
cat $WORK_FILE | $NANVAULT -p $VAULTPASS_FILE > $OUT_FILE
checkfiles

## LABEL

# encrypt with nanvault, decrypt with nanvault
cat $WORK_FILE | $NANVAULT -p $VAULTPASS_FILE -l mylabel | $NANVAULT -p $VAULTPASS_FILE > $OUT_FILE
checkfiles

# encrypt with nanvault, decrypt with ansible-vault
cat $WORK_FILE | $NANVAULT -p $VAULTPASS_FILE -l mylabel > $OUT_FILE
ansible-vault decrypt --vault-password-file $VAULTPASS_FILE $OUT_FILE
checkfiles

# encrypt with ansible-vault, decrypt with nanvault
ansible-vault encrypt --vault-id $VAULTPASS_FILE $WORK_FILE
cat $WORK_FILE | $NANVAULT -p $VAULTPASS_FILE > $OUT_FILE
checkfiles

## YAML strings

# to YAML with nanvault, from YAML with nanvault
Y_MYVAL="foo"
YEI_OUT=$(echo -n "$Y_MYVAL" | $NANVAULT -y mystuff | $NANVAULT -Y)
if [ "$YEI_OUT" != "$Y_MYVAL" ]
    then
        echo "YAML TESTS FAILED."
        exiterror
fi

# to YAML with ansible-vault, from YAML with nanvault
Y_MYVAL="foo"
YEI_OUT=$(echo -n "$Y_MYVAL" | ansible-vault encrypt_string --vault-password-file $VAULTPASS_FILE --stdin-name 'mystuff' | $NANVAULT -Y | $NANVAULT -p $VAULTPASS_FILE)
if [ "$YEI_OUT" != "$Y_MYVAL" ]
    then
        echo "YAML TESTS FAILED."
        exiterror
fi

# success, cleanup
cleanup
echo "SUCCESS!"
exit 0;

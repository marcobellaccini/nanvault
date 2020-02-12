#!/bin/bash
#
# Simple script to perform cross-tools tests
#
TEST_WORKDIR="tmp_crosstests"
VAULTPASS_FILE="${TEST_WORKDIR}/vaultpassfile"
PLAINTEXT_FILE="${TEST_WORKDIR}/plaintext"
WORK_FILE="${TEST_WORKDIR}/work"
OUT_FILE="${TEST_WORKDIR}/outfile"

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
echo -n "myfoopass" > $VAULTPASS_FILE
echo -n "test plaintext" > $PLAINTEXT_FILE

# generate workfile
cp $PLAINTEXT_FILE $WORK_FILE

## NO LABEL

# encrypt with nanvault, decrypt with nanvault
cat $WORK_FILE | ./bin/nanvault -p $VAULTPASS_FILE | ./bin/nanvault -p $VAULTPASS_FILE > $OUT_FILE
checkfiles

# encrypt with nanvault, decrypt with ansible-vault
cat $WORK_FILE | ./bin/nanvault -p $VAULTPASS_FILE > $OUT_FILE
ansible-vault decrypt --vault-password-file $VAULTPASS_FILE $OUT_FILE
checkfiles

# encrypt with ansible-vault, decrypt with nanvault
ansible-vault encrypt --vault-password-file $VAULTPASS_FILE $WORK_FILE
cat $WORK_FILE | ./bin/nanvault -p $VAULTPASS_FILE > $OUT_FILE
checkfiles

## LABEL

# encrypt with nanvault, decrypt with nanvault
cat $WORK_FILE | ./bin/nanvault -p $VAULTPASS_FILE -l mylabel | ./bin/nanvault -p $VAULTPASS_FILE > $OUT_FILE
checkfiles

# encrypt with nanvault, decrypt with ansible-vault
cat $WORK_FILE | ./bin/nanvault -p $VAULTPASS_FILE -l mylabel > $OUT_FILE
ansible-vault decrypt --vault-password-file $VAULTPASS_FILE $OUT_FILE
checkfiles

# encrypt with ansible-vault, decrypt with nanvault
ansible-vault encrypt --vault-id $VAULTPASS_FILE $WORK_FILE
cat $WORK_FILE | ./bin/nanvault -p $VAULTPASS_FILE > $OUT_FILE
checkfiles

# success, cleanup
cleanup
echo "SUCCESS!"
exit 0;

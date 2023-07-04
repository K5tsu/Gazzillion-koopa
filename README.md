# Gazzillion-Koopa
cool rootkit that opens a backdoor that can spawn a reverse shell to a remote host

launch malware and more

instructions:
1. download your kernel header files
[apt install linux-headers-$(uname -r)]
2. dir examples in the discord
3. clone the project and cd  Gazzillion-Koopa
4. build koopa by typing "make"
5. load koopa in the kernel and configure environment(thats where malware modules will be)
6. sudo ./install.sh
7. if you already ran the script and want to install koopa then sudo insmod ./koopa.ko
8. to unload sudo rmmod koopa but make sure it's not invisible

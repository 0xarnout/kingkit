# Kingkit is a rootkit designed for KOTH on tryhackme

### usage

Compile the rootkit with:
```
gcc kingkit.c -shared -fPIC -ldl -o kingkit.so
```
Then you can install the rootkit with:
```
cp ./kingkit.so /lib/kingkit.so
echo "/lib/kingkit.so" > /etc/ld.so.preload
```
Because of conflicting glibc versions you need to compile the rootkit on a koth machine. The easiest option is to compile on the food machine because it is available as a room, after you compiled it you can use that binary on all koth machines. Also make sure to change the macro KING_NAME to your own nickname.


### features
* [x] Protect and write name to king.txt
* [x] Redirect writes to /etc/ld.so.preload to FAKE_PRELOAD
* [x] Protect the rootkit library and FAKE_PRELOAD
* [x] Hiding files and directories starting with HIDE_PREFIX or with the gid equal to HIDDEN_GID
* [x] Reverse shell persistence
* [ ] Hiding processes and connections from netstat, ps and lsof
* [ ] Automatic restoration of the library after deletion


### file hiding
The rootkit hides files whose gid is equal to HIDDEN_GID and makes it impossible to do any file operations on it until the gid is changed with `chown` or `chgrp`. To hide a file you can run `chgrp HIDDEN_GID file_to_hide` where HIDDEN_GID is the HIDDEN_GID set in the rootkit, by default it is 5005. Apart from the HIDDEN_GID all files/directories starting with the HIDE_PREFIX are hidden from the directory listing, but they can still be accessed, they are only hidden from ls.


### process hiding
All processes with the gid equal to HIDDEN_GID are hidden from procfs and tools like `ps`. To set the gid you can use something like: `python3 -c 'import os;os.setgid(HIDDEN_GID);os.system("/bin/bash")'` where HIDDEN_GID is defined in the rootkit. Be careful with creating files, any files created by a process with HIDDEN_GID set will also be hidden and can only be accessed after setting a different gid, you can do that with: `chgrp root file_to_unhide`.


### reverse shell
The rootkit can spawn a reverse shell every minute by hooking the time() function in cron. To use this feature you have to change the HOST and PORT macros to your vpn ip address and the port netcat (or a different tool) is listening on. Additionally you have to restart the cron daemon so the rootkit is loaded by cron, to do that run `systemctl restart cron` on the machine after the rootkit is installed. The process is automatically hidden using the HIDDEN_GID.


### remove LD_PRELOAD rootkits
While LD_PRELOAD rootkits are very powerful, they have a critical weakness: static binaries are not affected. So to remove a LD_PRELOAD rootkit all you need is a static binary that removes the /etc/ld.so.preload file. To make things easier for you this repository already includes a static binary that removes the /etc/ld.so.preload file, run it with: `chmod +x remove && ./remove`. You can also compile it from source with `gcc remove.c -static -o remove`. Apart from the /etc/ld.so.preload file the LD_PRELOAD environment variable can also be used to load the malicious library. The environment variable can be removed with: `unset LD_PRELOAD`.


## resources about LD_PRELOAD rootkits

* [Memory Malware Part 0x2 — Crafting LD_PRELOAD Rootkits in Userland](https://compilepeace.medium.com/memory-malware-part-0x2-writing-userland-rootkits-via-ld-preload-30121c8343d5)
* [Creating a Rootkit to Learn C](https://h0mbre.github.io/Learn-C-By-Creating-A-Rootkit/)
* [awesome-linux-rootkits](https://github.com/milabs/awesome-linux-rootkits)
* [Awesome LD_PRELOAD (not hacking)](https://github.com/gaul/awesome-ld-preload)


## Note

> I am not responsible for any damage caused by this tool, make sure you understand what you are doing and use this tool for educational purposes only.

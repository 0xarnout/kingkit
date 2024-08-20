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
Because of conflicting glibc versions you need to compile the rootkit on the machine where you want to run it, otherwise it can break the machine. Also make sure to change the macro KING_NAME to your own nickname.


### features
* [x] Block any writing to king.txt
* [x] Redirect writes to /etc/ld.so.preload to FAKE_PRELOAD
* [x] Block writing to LIB_PATH and FAKE_PRELOAD
* [x] Write name to king.txt and protect it
* [x] Hiding files and directories starting with HIDE_PREFIX
* [ ] Reverse shell persistence
* [ ] Hiding processes and connections from netstat, ps and lsof
* [ ] Automatic restoration of the library after deletion


## Note

> I am not responsible for any damage caused by this tool, make sure you understand what you are doing and use this tool for educational purposes only.

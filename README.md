# zipbrk

Zip break is a tool to disect, modify, and reassemble zip files for a variety of tasks. It is designed to be cross-platform and as simple as possible to port from varied systems. It has been tested on Windows 9x/2k/XP, Windows Vista/7/8, Fedora 23/24, Kali 2017, Debian 8/9, Qubes 3.2, Whonix, FreeBSD 10.4/11.1, and various Android phones. Some examples of usage are:

**zipbrk file.zip --encryption-set --xor-crc32**
  
This command would tell zipbrk to set the encryption flag(s) in the file and modify the CRC32 sums associated with them. To modify the sums, the user is prompted for a password to be utilised as a key in any operations requiring unique modifications.

*Note that the encryption flag may be set, but the contents are still not necessarily encrypted. Zip file programs will typically prompt for a password if the encryption flag is set, and fail to realise the data is not even encrypted, but the data is actually still in a plaintext form.*



A safer alternative would be to perhaps encrypt a zip file, and then make it appear as though it's not encrypted, which may lead a user to assume the file is damaged.

**--encryption-unset**


Some anti-virus softwares have been known to not scan the contents of a file if the Uncompressed Size parameter of the file header is set to 0 bytes in size.

**--zero-uncompressed**


In the event that a provider does not permit the transmission or storage of zip files (e.g. GMail, et al.) then the zip file signature can be changed to fool zip processors into assuming the file is not in zip format. The signature can then be changed back once it is received by the end-point.

**--signature-spoof**

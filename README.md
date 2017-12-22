# zipbrk

Zip break is a tool to disect, modify, and reassemble zip files for a variety of tasks. Some examples of usage are:

  zipbrk file.zip --encryption-set --xor-crc32
  
This command would tell zipbrk to set the encryption flag(s) in the file and modify the CRC32 sums associated with them. To modify the sums, the user is prompted for a password to be utilised as a key in any operations requiring unique modifications.

Note that the encryption flag may be set, but the contents are still not necessarily encrypted. Zip file programs will typically prompt for a password if the encryption flag is set, and not realise the data is not even encrypted.

An alternative would be to perhaps encrypt a zip file, and then make it appear as though it is not encrypted, which may lead a user to assume the file is damaged. Some anti-virus softwares have been known to not scan the contents of a file if the Uncompressed Size parameter of the file header is set to 0 bytes in size. In the event that a provider does not permit the transmission or storage of zip files (e.g. GMail, et al.) then the zip file signature can me changed to fool zip processors into assuming the file is not in zip format. The signature can then be changed back once it is received by the end-point.

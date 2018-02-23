# hashcheck
Simple file hash tool for the command line.

  - Quickly print the hashes of a single file or all files in a directory.
  - Quickly check if a hash matches a single file or any file in a directory.

Requires Python 3. Use the -r flag to traverse directories recursively.

Utilizes the hashlib module which supports the FIPS secure hash algorithms SHA1, SHA224, SHA256, SHA384, and SHA512 (defined in FIPS 180-2) as well as RSA’s MD5 algorithm.

Usage tip:
Make it executable, rename and remove the .py extension, put it in your $PATH.

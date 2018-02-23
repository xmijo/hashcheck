#!/usr/bin/env python3

# Simple file hash checker
# github.com/xmijo/hashcheck

# Get the hash of a single file or all files in a directory
# or check if a hash matches any of the files.

import argparse
import hashlib
import sys, os

digests = {
    'md5': hashlib.md5,
    'sha1': hashlib.sha1,
    'sha224': hashlib.sha224,
    'sha256': hashlib.sha256,
    'sha384': hashlib.sha384,
    'sha512': hashlib.sha512,
}

default_digests = [
    'md5',
    'sha1',
]


def get_args():
    description = 'Simple file hash checker.'
    ap = argparse.ArgumentParser(
        description=description,
        epilog='Inputfile required.'
        )
    ap.add_argument(
        'filepath',
        nargs='?',
        #metavar='FILE',
        default=os.getcwd(),
        help='single file or filepath (default: current directory)'
    )
    ap.add_argument(
        '-d',
        dest='digest',
        # nargs='+',
        choices=digests,
        default=default_digests,
        help='specify digests. (default: md5, sha1)'
    )
    ap.add_argument(
        '-c',
        metavar='HASH',
        dest='compare',
        help='hash to compare'
    )
    return ap.parse_args()


def checkhash(inputfile, digest):
    try:
        filehash = digests[digest]()
        with open(inputfile, 'rb') as workfile:
            # Read by chunks to save memory in case of large filesize
            for chunk in iter(lambda: workfile.read(65536), b''):
                filehash.update(chunk)
        return filehash.hexdigest()
    except FileNotFoundError:
        sys.exit(f'[!] File not found: {inputfile}')

def verifyhash(hash1, hash2):
    if hash1 == hash2:
        return True

def enum_files(filepath):
    filelist = []
    if os.path.isfile(filepath):
        filelist.append(filepath)
    elif os.path.isdir(filepath):
        for root, dirs, files in os.walk(os.path.abspath(filepath)):
            [filelist.append(os.path.join(root, file)) for file in files]
        filelist = sorted(filelist)
    return filelist

def enum_hashes(filelist, digests):
    output = {}
    for file in filelist:
        output.update(
            {file: {digest: checkhash(file, digest) for digest in digests}})
    return output

def print_output(outputlist):
    indent = max(len(digest) for file, digests in outputlist.items() for digest in digests) + 2
    for file, digests in outputlist.items():
        print(file)
        for digest, value in digests.items():
            print('{:>{i}}: {}'.format(digest, value, i=indent))
        print('')

def main():
    args = get_args()

    filelist = enum_files(args.filepath)
    print(f'[*] Processing {len(filelist)} file(s)\n')

    output = enum_hashes(filelist, args.digest)

    if args.compare:
        hashmatch = None
        for file, digests in output.items():
            for digest, value in digests.items():
                if verifyhash(value, args.compare):
                    hashmatch = True
                    output = {}
                    output.update({file: {digest: value}})
                    print_output(output)
                    print(f'[+] Found matching {digest} hash: {args.compare}\n')
        if not hashmatch:
            print(f'[-] No matching hash')
    else:
        print_output(output)


if __name__ == '__main__':
    main()

#!/usr/bin/env python3

# Simple file hash checker
# github.com/xmijo/hashcheck

# Get the hash of a single file or all files in a directory
# or check if a hash matches any of the files.

import argparse
import hashlib
import sys
import os

hash_algos = {
    'md5': hashlib.md5,
    'sha1': hashlib.sha1,
    'sha224': hashlib.sha224,
    'sha256': hashlib.sha256,
    'sha384': hashlib.sha384,
    'sha512': hashlib.sha512,
}

default_hash_algos = [
    'md5',
    'sha256',
]


def get_args():
    description = 'Simple file hash checker.'
    ap = argparse.ArgumentParser(
        description=description,
        )
    ap.add_argument(
        'filepath',
        nargs='?',
        #metavar='FILE',
        default=os.getcwd(),
        help='single file or filepath (default: current directory)'
    )
    ap.add_argument(
        '-r',
        '--recursive',
        action='store_true',
        help='traverse directories recursively'
    )
    ap.add_argument(
        '-a',
        dest='hash_algo',
        nargs='+',
        choices=hash_algos,
        default=default_hash_algos,
        help='specify hashing algorithms. (default: md5, sha1)'
    )
    ap.add_argument(
        '-c',
        '--check',
        metavar='HASH',
        dest='compare',
        help='check file(s) for matching hash'
    )
    return ap.parse_args()


def checkhash(inputfile, hash_algo):
    try:
        filehash = hash_algos[hash_algo]()
        with open(inputfile, 'rb') as workfile:
            # Read by chunks to preserve memory in case of large filesize
            for chunk in iter(lambda: workfile.read(65536), b''):
                filehash.update(chunk)
        return filehash.hexdigest()
    except FileNotFoundError:
        sys.exit(f'[!] File not found: {inputfile}')

def verifyhash(hash1, hash2):
    if hash1 == hash2:
        return True

def enum_files(filepath, recursive):
    filelist = []
    if os.path.isfile(filepath):
        filelist.append(filepath)
    elif os.path.isdir(filepath):
        for root, dirs, files in os.walk(os.path.abspath(filepath)):
            [filelist.append(os.path.join(root, file)) for file in files]
            if not recursive:   # break loop after current dir if non-recursive
                break
    else:
        sys.exit(f'[!] {filepath} not found!')
    if len(filelist) == 0:
        sys.exit('[!] No file(s) to enumerate!')
    if len(filelist) > 1:
            filelist = sorted(filelist)
    return filelist

def enum_hashes(filelist, hash_algos):
    output = {}
    for file in filelist:
        output.update(
            {file: {hash_algo: checkhash(file, hash_algo) for hash_algo in hash_algos}})
    return output

def print_output(outputlist):
    indent = max(len(hash_algo) for file, hash_algos in outputlist.items() for hash_algo in hash_algos) + 2
    for file, hash_algos in outputlist.items():
        print(file)
        for hash_algo, value in hash_algos.items():
            print('{:>{i}}: {}'.format(hash_algo, value, i=indent))
        print('')

def main():
    args = get_args()

    filelist = enum_files(args.filepath, args.recursive)
    print(f'[*] Processing {len(filelist)} file(s)\n')

    output = enum_hashes(filelist, args.hash_algo)

    if args.compare:
        hashmatch = None
        for file, hash_algos in output.items():
            for hash_algo, value in hash_algos.items():
                if verifyhash(value, args.compare):
                    hashmatch = True
                    output = {}
                    output.update({file: {hash_algo: value}})
                    print_output(output)
                    print(f'[+] Found matching {hash_algo} hash: {args.compare}\n')
        if not hashmatch:
            print(f'[-] No matching hash')
    else:
        print_output(output)

if __name__ == '__main__':
    main()

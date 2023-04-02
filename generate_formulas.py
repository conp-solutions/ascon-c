#!/usr/bin/env python3

import argparse
import logging
import os
import random
import string
import subprocess
import sys

log = logging.getLogger(__name__)


def execute(cmd):
    log.debug("Execute command %r", cmd)
    process = subprocess.Popen(cmd,
                        stdout=subprocess.PIPE, 
                        stderr=subprocess.PIPE, shell=True)
    stdout, stderr = process.communicate()
    log.debug("Stdout: %s", stdout)
    log.debug("Stderr: %s", stderr)
    return stdout

def build_showhash():
    if not os.path.exists("./showhash"):
        cmd = "gcc -march=native -O3 -Icrypto_hash/asconhashv12/opt64 crypto_hash/asconhashv12/opt64/*.c -Itests tests/list_hash.c -o showhash"
        execute(cmd)
    else:
        log.info("Detected showhash binary already")

def generate_random_string(N=32):
    return ''.join(random.choices(string.ascii_lowercase + string.ascii_uppercase + string.digits, k=N))

def generate_C_file(c_file_name, input_text, hash, drop_bytes):
    
    first_program = """\
#include <assert.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api.h"
#include "crypto_hash.h"

int main(int argc, char* argv[]) {

    /* put on stack, to allow CBMC to initialize values */
    unsigned char __attribute__((aligned(16))) m[MAX_INPUT_SIZE + 1];
    unsigned char __attribute__((aligned(16))) h[CRYPTO_BYTES];

    for (int i = 0 ; i < CRYPTO_BYTES; ++i) h[i] = 0;
    m[MAX_INPUT_SIZE] = 0;
    
    /* START Initialize message buffer */
    """.replace("MAX_INPUT_SIZE", str(len(input_text)))
    
    init_string = ""
    for i in range(0, len(input_text)):
        char_int = ord(input_text[i])
        log.debug("Convert input character %s into int %d", input_text[i], char_int)
        if False or i in drop_bytes:
            init_string += f"    /* m[{i}] = {char_int}; // leave uninitialized ... */\n"
        else:
            init_string += f"    m[{i}] = {char_int};\n"

    second_program = """
    /* END Initialize message buffer */
    
    int r = crypto_hash(h, m, MAX_INPUT_SIZE);

    printf("Hashing return code: %d\\n", r);
    printf("Hashing '%s' results in hash:\\n", m);
    
    #ifndef __CPROVER__
    for (int i = 0 ; i < CRYPTO_BYTES; ++i) {
        printf("h[%d] == %d && \\n", i, (int)h[i]);
    }
    #endif

    int success = (
    HASHCONDITION
    );

    assert(!success); // target for CBMC, needs to fail to find the correct missing values

    if (success == 1) {
        printf("Hash matches\\n");
    } else {
        printf("Hash does not match\\n");
    }

    return 0;
}
""".replace("MAX_INPUT_SIZE", str(len(input_text)))

    second_program = second_program.replace("HASHCONDITION", hash)

    program = first_program + init_string + second_program

    with open(c_file_name, 'w') as outfile:
        outfile.write("/* Norbert Manthey, ASCON hashv12 */\n")
        outfile.write(program)
    
    # generate the CNF out of the 1 binary we create, and remove the binary afterwards
    execute(f"goto-gcc -march=native -O3 -Icrypto_hash/asconhashv12/opt64 crypto_hash/asconhashv12/opt64/*.c -Itests -o attack_hash {c_file_name}")
    # execute("cbmc --property main.assertion.1 --no-built-in-assertions attack_hash")

    outfile = f"{c_file_name}.cnf"
    execute(f"cbmc --property main.assertion.1 --no-built-in-assertions --reachability-slice --dimacs --outfile {outfile} attack_hash")


def generate_formulas(input_len=32, missing_bytes=2):

    test_text = generate_random_string(input_len)
    log.info("test_text: %s", test_text)

    hash_condition = execute(f"./showhash {test_text}").decode().strip()
    log.info("Full hash condition: %s", hash_condition)


    input_bytes = len(test_text)
    drop_bytes = sorted(random.sample(range(0, input_bytes-1), missing_bytes))
    log.debug("Drop bytes %r from total %d bytes", drop_bytes, input_bytes)

    missing_name = '_'.join([str(x) for x in drop_bytes])

    c_file_name=f"asconhashv12_opt64_H{len(test_text)}_M{missing_bytes}-{test_text}_m{missing_name}.c"
    generate_C_file(c_file_name, test_text, hash_condition, set(drop_bytes))


def main():
    logging.basicConfig(
        format="%(asctime)s,%(msecs)d %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s",
        datefmt="%Y-%m-%d:%H:%M:%S",
        level=logging.DEBUG,
    )

    parser = argparse.ArgumentParser(description="Generate ASCON hash attack formulas")

    parser.add_argument(
        "-n",
        "--input-len",
        default=24,
        type=int,
        help="Number of random bytes to be hashed",
    )
    parser.add_argument(
        "-m",
        "--missing-bytes",
        default=1,
        type=int,
        help="Number of characters to be guessed",
    )
    args = parser.parse_args()
    args = vars(args)

    build_showhash()

    generate_formulas(**args)


if __name__ == "__main__":
    sys.exit(main())
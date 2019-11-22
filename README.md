# keyfinder

Author: Michal Malik


A tool for differential cryptanalysis of a basic SPN cipher: 4x4 S-box, 16bit input/output, 5 rounds, 80bit key, 16bit round keys.
Keyfinder can recover **the whole key** by itself. You don't have to find trajectories (paths) manually.


Implemented for an assignment for 'Design and cryptanalysis of ciphers' at FEI STU, Bratislava, 2019 led by prof. Ing. Pavol Zajac, PhD.


Last subkey recovery http://www.engr.mun.ca/~howard/PAPERS/ldc_tutorial.pdf


## How to compile

### Windows

Tested with:
- MSVC 2019
- MSVC 2017

Open the solution, choose the Release x64 build and build it.

### macOS, Linux

1. Go to KeyFinder/Generator folder
2. make

Tested with:
- Apple clang version 11.0.0 (clang-1100.0.33.12)

## Usage
      KeyFinder [OPTION...] <CIPHERTEXT_LIST> <SBOX>

      -h, --help                    Print help
      -v, --verbose N               Print more descriptive messages. 1 = more
                                    info, 2 = medium info, 3 = VERY detailed
          --ciphertext_list filename
                                    List of ciphertexts, each line in hhhh
                                    format.
          --sbox arg                Space separated decimal values <0,15> for
                                    sbox, e.g: "6 10 11 15 12 2 13 5 3 8 0 1 14 7 4
                                    9"
      -t, --threads N               Number of threads to use (default: 1)
          --heur3                   Use 3 sboxes for subkey computation when
                                    generating best paths. More accurate than just 2
                                    sboxes (default), but ~10x slower.
          --heur4                   Use 4 sboxes for subkey computation when
                                    generating best paths. Best accuracy, but takes
                                    ~5x longer than 3 sboxes. This enables --heur3
                                    as well.

     Mode options:
      -f, --first                  Calculate first subkey only
      -l, --last                   Calculate last subkey only
          --backward key5,key4,..  Used to calculate a specific subkey
                                   (backward). Next one after given will be calculated. List
                                   of comma-separated subkeys to use (before the
                                   one(s) you want, going from right to left),
                                   last subkey first, format hhhh.
      -a, --find-all               Try to find all subkeys. This enables Heur3
                                   and Heur4. CAUTION: THIS TAKES A LONG TIME!
          --test-key key           Given a key in aaaabbbbccccddddeeee format,
                                   test if encrypting plaintexts results in given
                                   ciphertexts
      -d, --diff-table             Print diff table for the given sbox

## Example key

    aaaabbbbccccddddeeee

Which means (in hex)

    key[4] = eeee
    key[3] = dddd
    key[2] = cccc
    key[1] = bbbb
    key[0] = aaaa

## Example input file 

    
    1b5e
    5694
    1f3e
    5f9e
    92db
    f2df
    1f9e
    d6db
    9f9b
    1b9b
    b63b
    5b9e
    ff3f
    ...

## Example S-box

    "6 10 11 15 12 2 13 5 3 8 0 1 14 7 4 9"

## Recommended switches

- heur4 = enables computation of 3 and 4 sboxes, very slow without multithreading
- t <num_threads> = use this if you are using --heur3 or --heur4
- v <level> = verbose level enabled, you can see the progress and such (3 is very noisy)

## Example usage

### Recover full key

    $ keyfinder out.txt "6 10 11 15 12 2 13 5 3 8 0 1 14 7 4 9" -a -t 4
    
### Recover first subkey only

    $ keyfinder out.txt "6 10 11 15 12 2 13 5 3 8 0 1 14 7 4 9" -f

### Recover last subkey only

    $ keyfinder out.txt "6 10 11 15 12 2 13 5 3 8 0 1 14 7 4 9" -l

### Recover 4th subkey using last subkey

    $ keyfinder out.txt "6 10 11 15 12 2 13 5 3 8 0 1 14 7 4 9" --backward <key5> --heur4 -t 4

### Recover 3th subkey using key5, key4

    $ keyfinder out.txt "6 10 11 15 12 2 13 5 3 8 0 1 14 7 4 9" --backward <key5>,<key4> --heur4 -t 4

### Test if the guessed key is correct

    $ keyfinder out.txt "6 10 11 15 12 2 13 5 3 8 0 1 14 7 4 9" --test-key aaaabbbbccccddddeeee

## Benchmarks

Tested with:
- Windows 10 build 1903
- i5-4670 3.4 GHz
- 12GB RAM
- Release binary from MSVC 2019 16.1.2
- Sbox used: "6 10 11 15 12 2 13 5 3 8 0 1 14 7 4 9"

Result:

    will use 4 thread(s)
    will use 3 sboxes!
    will use 4 sboxes!
    starting full key recovery..
    guessing key[4]..
    took: 0.085s
    guessed key[4] = 45cb
    key[4]=45cb
    guessing key[3]..
    doing 3 sboxes for key[3]
    doing 3 sboxes for key[3]
    doing 3 sboxes for key[3]
    doing 3 sboxes for key[3]
    doing 4 sboxes for key[3]
    took: 111s
    guessed key[3] = 80a6
    key[3]=80a6
    guessing key[2]..
    doing 3 sboxes for key[2]
    doing 3 sboxes for key[2]
    doing 3 sboxes for key[2]
    doing 3 sboxes for key[2]
    doing 4 sboxes for key[2]
    took: 109.49s
    guessed key[2] = 875a
    key[2]=875a
    guessing key[0]..
    took: 0.072s
    guessed key[0] = f993
    key[0]=f993
    looking for key[1]..
    found key[1] = c0f7
    took: 0.001s
    key[1]=c0f7
    took: 220.654s
    full key: f993c0f7875a80a645cb 

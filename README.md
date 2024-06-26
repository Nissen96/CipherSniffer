# CipherSniffer

CipherSniffer helps automate the process of identifying cryptographic algorithms in binaries.

It helps detect a number of ciphers, hash algorithms, and encoding schemes.

## Installation

The script can be downloaded and run with Python 3 as is with no external dependencies.

Optionally, `tqdm` can be downloaded for progress bar support, which is helpful for larger binaries:

```bash
python3 -m pip install tqdm
```

## Usage

```
Usage: ciphersniffer.py [-h] [-p] [-f FILTER] [-l] [file]

Detect cryptographic algorithms in binary data

positional arguments:
  file                  Binary data file

options:
  -h, --help            Show this help message and exit
  -p, --progress        Show progress bars
  -f FILTER, --filter FILTER
                        Algorithm(s) to detect, e.g. 'cha,md,zip'
  -l, --list            List supported algorithms
```

The script defaults to detecting all supported algorithms.
To target the search, `--filter` can be used with a comma-separated list of values.
Any algorithm containing the value in its name will be run, so `md` matches both `MD4` and `MD5`.

## Notes

Detection is based on fixed constants often seen for each algorithm, such as the S-box in AES or round constants for SHA-256.

The script searches for constants sequentially in the data, but they only need to be in order, not necessarily consecutive.
If not consecutive, the match is marked as `(fragmented)`.'
A match is considered consecutive if all values are within 256 bytes of the next to take padding etc. into account.

Full matches are more reliable than partial, consecutive more than fragmented, and long more than short.

Green matches are full and consecutive, but if short might still be a false positive.

Yellow matches are partial or fragmented, but can still be valid.

- *Example:* Searching for `ABC` in `.A...ABC..`, the matches found are `.A....BC..` although the sequence exists consecutively.

Checking each combination would decrease the speed dramatically, and the result can just be verified manually instead.

## Contributing

Contributions are welcome. To contribute, please fork the project, develop your feature on a new branch, and create a new pull request with the changes.

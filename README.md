# zapalyzer
Parse ZAProxy JSON alert report file

It doesn't require any additional libraries, so you are good to go with any recent python version

Currently it will output the results to `stdout` in CSV format

## Options
```
$ ./zapalyzer.py -h                                            
usage: zapalyzer.py [-h] [-i file] [--csv] [--nocsv] [--cve] [--apikey <API key>]

Analyze ZAProxy JSON alert report

options:
  -h, --help            show this help message and exit
  -i file, --input file
                        Path to the JSON report file
  --csv                 Print the results in CSV format (default)
  --nocsv               Don't output results in CSV format
  --cve                 Add CVE base score and vector to output, by performing a lookup on NIST NVD database
  --apikey <API key>    NVD database API key to speed up CVE lookup
```


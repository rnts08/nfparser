nfparser
========

This script will pull and format data from nfcapd, update the configuration in the beginning of the script
and have a go.

Usage: ./nfparser.py        Runs a single nfparser that dumps TopN in each direction. 

Usage: ./nfparser.py 1234   Searches for AS1234 in the last 5 minutes nfcapd files.

New for this version is;

* Consolidated nfparser and nfparser_search
* New 'createFileName' method that actually checks the directories for the last-1 file
* Configuration moved to the top of the file


TODO:

- Move configuration to configuration file
- Figure out if the new createFileName is actually better than the old one
- Drink more beer

NOTE! This script is provided as-as and I'm not responsible for what you might do with it, exploding your routers or crashing harddrives is your problem, not mine. :-)



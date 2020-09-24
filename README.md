# Breaking Good

## About
Tool developed with the objective of generating adversary malware, from existing malicious software, that are capable of evading some modern antivirus' techniques. Written by Gabriel Lüders, an undergraduate student from UFPR - Brazil.


## Contributors
  - Advisor
    - André Grégio
  - Marcus Botacin
  - Fabrício Ceschin
### Get to know us better accessing [SECRET - SEcurity & Reverse Engineering Team](https://secret.inf.ufpr.br/)


## Goals

Series of python scripts that modify malware by adding strings, raw binary data, changing int3 instructions and realocaing returns and submits them to the Virus Total API in order to find flaws in common used antivirus so that they can be enhanced and have a wider range of detection.

The scripts use [Pefile](https://pypi.org/project/pefile/) to identify the malware's sections, in particular the ones with executable code, and feed them to [Capstone](http://www.capstone-engine.org/) so a disassemble can be generated and futurally modified by the functions described in the scripts, wich will generate md5-hashed files that are sent to [Virus total](https://www.virustotal.com/gui/home/upload).


## Dependencies
  - pefile==2019.4.18
    - pefile must be installed for python3 and python2
  - requests==2.22.0
  - capstone==4.0.2
  - termcolor==1.1.0
  - python_magic==0.4.18
  - injection.py
    - script written by [Alexandre CHERON](https://axcheron.github.io/code-injection-with-python/)



## Supported Modifications
  - append raw binary data
    - Appends raw binary data returned by the bash command ```us.random``` with a fixed length of 50
  - append goodware strings
    - appends strings extrected from the dll passed by the user using the bash command ```strings```
  - change int3 instructions
    - substitutes int3 instructions by a pair of add and sub instructions whenever possible
  - swap ret instructions with nop instructions
    - changes the organization of the code by swapping nop instructions with the ret instruction directly above
  - Append Goodware Sections
    - using an injector, appends execuble code from the dll into the malware


## Running
### Getting a key
  - In order to use the API you must sign up to VirusTotal Community. Once you have a valid VirusTotal Community account you will find your personal API key in your personal settings section
  - For more information, go to the [Virus Total API](https://developers.virustotal.com/reference#getting-started) and follow the steps.
  - After you get the key, assign it to the "key" variable in the BreakingGood/Files/config.cfg configuration file 


### To test with the files in this repository:

```
  cd BreakingGood/Files
  python3 main.py
```
- main.py works with either the config.cfg file present in the same directory or, if config.cfg is not present, via command line arguments

### Using breakingood as a module

```
  from breakingood import Breakingood

  bg = Breakingood()
  bg.build_adversaries(malwarePath, goodwarePath, resultsPath)
  bg.handle_virus_total(resultsPath, key)
  bg.handle_results_table(resultsPath)

```


### For more information on how to run it: 

```
  python3 main.py -h
```

## Results
  The table bellow is an exemple output of the program if execution is successful. It represents the impact each modification had on the sample when it was submitted for analysis.
  
  - False: not a malware
  - True: a malware

 ![Alt text](./results.png "Example of a Detection Table")



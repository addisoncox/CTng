# Next Generation Certificate Transparency:

## Function Documentation
Documentation + Function descriptions exist in each file/subfolder.

## Folders for implemetations:

**`config`**: Contains the layout of private and public json configuration files used by Monitors and Gossipers. 

**`crypto`**: Abstractions associated with CTng cryptographic implementations, and the cryptoconfig implementation.

**`gossip`**:  All gossiper related functions

**`monitor`**: All monitor related functions

**`ca`**: All ca related functions

**`logger`**: All logger related functions

**`client`**: All client related functions

**`util`**: a package that has no internal imports: helper functions and constants that are used throughout the codebase but prevents import cycles from occurring (import cycles are not allowed in go).

## Folders for Testing 


**`gen`**: generates all config files for all entities within the network topology

**`client_test`**: Contains all the config and data to test the just the client  

**`logger_ca`**: Contains all the config and data to test
1) Logger-CA API
2) Logger-Monitor API
3) CA-monitor API

**`network`**: Contains all the config and data to test
1) Logger-CA API
2) Logger-Monitor API
3) CA-monitor API
4) monitor-gossiper API
5) Inter-gossiper API

Note: those folders will also contain some output files after running the test

___

## Running the network test

Run `go install .` before continuing!

To run on Linux or WSL2:

- `sh 3344.sh`  

if the sh file format is not working, try 
- `dos2unix 3344.sh`

The test data includes 3 CAs, 3 loggers, 4 monitors, 4 gossipers

To close all tmux sessions, you can use command:

- `tmux kill-server`

To evaluate the output, navigate to the network folder and execute:

- `go test`

####Note: let the system run for more than 3 min before you start the evaluation. 

### Licensing
Both imports we use, gorilla/mux and herumi/bls-go-binary, use an OpenBSD 3-clause license. as a result, we use the same Please see LICENSE in the outer folder for details.

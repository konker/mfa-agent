# mfa-agent
------------------------------------------------------------------------------


An agent which can be instantiated to provide secrets from a keepassx database.

## POA
### Overview
1) config file:
    - alias -> specific keepassx database item

2) start agent:
    - specify keepassx database file
    - specify password
    - open database
    - read data specified in config into memory
    - close database

3) query agent:
    - specify alias -> get secret

### Implementation
- daemon to reside in memory with data
- command line program to query daemon
    - IPC?
    - UDP?


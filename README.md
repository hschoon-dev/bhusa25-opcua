# Test of OPC UA attack tool from Blackhat USA '25 on asyncua server

Python tool to automate the OPC UA attacks described in Tom Tervoort's talk "[No VPN Needed? Cryptographic Attacks Against the OPC UA Protocol](https://www.blackhat.com/us-25/briefings/schedule/index.html#no-vpn-needed-cryptographic-attacks-against-the-opc-ua-protocol-44760)", and to evaluate whether an OPC UA endpoint is potentially vulnerable.
This version implements a test setup using asyncua's OPC UA Server with different *SecurityPolicies*.

## Usage
    $ ./opcattack.py -h
    usage: opcattack.py [-h] attack ...
    
    Proof of concept tool for attacks against the OPC UA security protocol.
    
    positional arguments:
      attack            attack to test
        check           evaluate whether attacks apply to server
        reflect         authentication bypass via reflection attack
        relay           authentication bypass via relay attack between two servers
        cn-inject       path injection via an (untrusted) certificate CN
        auth-check      tests if server allows unauthenticated access
        decrypt         sniffed password and/or traffic decryption via padding
                        oracle
        sigforge        signature forgery via padding oracle
        client-downgrade
                        password stealing downgrade attack against a client
    
    options:
      -h, --help        show this help message and exit

Run `opcattack.py <command> -h` to get help for configuration options of a specific attack.

## Installation
```terminal
docker compose up --build -f <file-name>
```

## Usage
```terminal
# Example commands for different test arguments:
docker compose run --rm --entrypoint "" opcattack python opcattack.py check -t opc.tcp://opcua-server:4840

docker compose run --rm --entrypoint "" opcattack python opcattack.py sigforge opc.tcp://opcua-server:4840 -T <treshhold value in seconds> -C <counter value> <hex-stream from e.g. wireshark>
```
The entrypoint from the [original test tool](https://github.com/bvcyber/opcattack) will be overwritten by *--entrypoint ""* in order to allow the use of a docker-network.

# mbedCrypto
## _Free open source cryptolibrary for embedded systems_
#### Dev version: 0.1.0
[![Build Status](https://app.travis-ci.com/Zontec/mbedCrypto.svg?branch=dev)](https://app.travis-ci.com/Zontec/mbedCrypto) [![seccode](https://img.shields.io/badge/code-SEI/CERT-brightgreen.svg?style=flat)](https://wiki.sei.cmu.edu/confluence/display/c/SEI+CERT+C+Coding+Standard) [![code style](https://img.shields.io/badge/code%20style-c/cpp-brightgreen.svg?style=flat)](https://google.github.io/styleguide/cppguide.html)

## Description

**_mbedCrypto_** is a crossplatform, open source, free to use and modify cryptolibrary for embedded devices and software.
The key idea is to provide flexibal usage with support both FW and HW at the same time. Each cryptoalgotihthm can be successfuly used independently that allows to use for example HW SHA implementation with FW HMAC.
The project use both regular and special tests. Regular tests are: unit, functional and system. Special tests are algorithm dependent. For FIPS standardized algorithms CAVP testing is used.For that purpose created a special [**framework**](https://github.com/Zontec/CAVP_Tester).
The library includes wide documentation with doxygen, proper codestyle and CERT implementation.

## Features

- Easy to use
- Wide range of algorithms
- Can be used both for embedded systems and for software applications
- Independent algorithm implementation
- Supports 3 secure levels
- Side attack protection
- Simple and wide library configuration

## Arch

By default library supports a set of different architectures. Architecture dependent implementation can support both native compilation and crosscompilation. 
Supported architectures:
- X86-32
- X86-64
- ARM32
- ARM64


## Configuration

Before to be compiled for testing or usage as a compiled library the project has to be configured. It can be done manually or by KConfig.
Via TUI:
```sh
make menuconfig
```
Via console:
```sh
make config
```
CI/CD use special configuration with name ```test.config```. By default config file use name ```.config```.

## Build

The library can be successfully used both as a plain sources and compiled libraries(shared, static). 
Build to test:
```sh
make tests
```
Build shared lib:
```sh
make shared
```
Build static lib:
```sh
make static
```

## Testing

To start unit, functional and system tests the library should be configured first. Then build with `make tests:`
```sh
make clean
make tests_config
make tests
./mbcrypt_tests
```

CAVP tests ....

## Dependencies

| LIB | URL |
| ------ | ------ |
| libtommath | [libtommath][libtommath] |
| cmocka | [cmocka][cmocka] |
| CAVP_Tester | [CAVP_Tester][CAVP_Tester] |

## Development

Want to contribute? Great!

Library use special projects for different purposes. 

Regarding to crypto algorithm. Each of them has four stages:
- Zero(0) - algorithm not implemented at all or implemented not enough
- Raw(1) - stage when a base set of operation implemented with a minimum security level and protection
- PreRelease(2) - algorithm has all the protections and main implementations 
- Release(3) - the last stage. Algorithm can be used for any purposes. Has lots of tests and protections. Supports all the architectures present.

Also prefix `+` means algorithm has full testing. e.g. In change log SHA256__2+ means that SHA256 in PreRelease state with fully covered with tests. 

See PR_TEMPLATE or BUG_REQUEST template.

## Change log
....
## Change log
....
## License
....

[//]: # (These are reference links used in the body of this note and get stripped out when the markdown processor does its job.)

   [libtommath]: <https://github.com/libtom/libtommath>
   [cmocka]: <https://github.com/clibs/cmocka>
   [CAVP_Tester]: <https://github.com/Zontec/CAVP_Tester>
   

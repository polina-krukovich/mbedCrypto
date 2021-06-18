
SRCS += sha1.c
SRCS += sha256.c
SRCS += sha512.c

SRCS += hmac_sha1.c
SRCS += hmac_sha256.c
SRCS += hmac_sha512.c

SRCS += pbkdf2.c
#SRCS += kbkdf.c
#SRCS += bignum.c
#SRCS += rsa.c
SRCS += rand.c
SRCS += aes.c

all:
	@rm -f run_tests.out
	@gcc -w -g self_tests.c $(SRCS) -I./includes/ -lcrypto -lssl -o run_tests.out

	@echo "Compilation done!"

.PHONY docs:
	doxygen dox/doxygen.cfg

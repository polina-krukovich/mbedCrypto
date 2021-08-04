SRC_DIR=src
SRCS =  $(SRC_DIR)/self_tests.c				\
		$(SRC_DIR)/mbcrypt_utils.c			\
		$(SRC_DIR)/sha1.c 					\
		$(SRC_DIR)/sha256.c 				\
		$(SRC_DIR)/sha512.c					\
		$(SRC_DIR)/hmac.c					\
#		$(SRC_DIR)/pbkdf2.c					\
#		$(SRC_DIR)/kbkdf.c					\


#SRCS += rsa.c
#SRCS += drbg.c
#SRCS += aes.c
#SRCS += rc4.c
#SRCS += entropy.c

all:
	@rm -f run_tests.out
	@gcc -w -g  $(SRCS) -I./includes/ -lcrypto -lssl -o run_tests.out

	@echo "Compilation done!"

sha1_test:
	@rm -f sha1_test.out
	@gcc -w -g sha1_test.c sha1.c -I./includes/ -lcrypto -lssl -o sha1_test.out


.PHONY docs:
	doxygen dox/doxygen.cfg

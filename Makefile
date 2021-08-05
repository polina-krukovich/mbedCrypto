SRC_DIR=src
SRCS =  $(SRC_DIR)/self_tests.c				\
		$(SRC_DIR)/mbcrypt_utils.c			\
		$(SRC_DIR)/sha1.c 					\
		$(SRC_DIR)/sha256.c 				\
		$(SRC_DIR)/sha512.c					\
		$(SRC_DIR)/hmac.c					\
		$(SRC_DIR)/pbkdf2.c					\
		$(SRC_DIR)/kbkdf.c					\


#SRCS += $(SRC_DIR)/rsa.c
#SRCS += $(SRC_DIR)/drbg.c
#SRCS += $(SRC_DIR)/aes.c
#SRCS += $(SRC_DIR)/rc4.c
#SRCS += $(SRC_DIR)/entropy.c

all:
	@rm -f run_tests.out
	@gcc -w -g  $(SRCS) -I./includes/ -lcrypto -lssl -o run_tests.out

	@echo "Compilation done!"

.PHONY docs:
	doxygen dox/doxygen.cfg

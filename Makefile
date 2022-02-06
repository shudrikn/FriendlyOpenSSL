LIB_DIR = ./../../lib
INCLUDE_DIR = ./../../include

#CXXFLAGS += -g -Wall -Wextra -pthread

DEBUG = n

ifeq (${DEBUG},y)
	DEBFLAGS = -O0 -g -ggdb -DDEBUG
	CONFIGURATION = debug
else
	DEBFLAGS = -O2 -DNDEBUG
	CONFIGURATION = release
endif

ifneq (, $(findstring linux, ${platform}))
	ifneq (, $(findstring x86_64, ${platform}))
		OPENSSL_LIBDIR = $(LIB_DIR)/openssl1.1._/Linux_x64
		RTENGINE_LIBDIR = $(LIB_DIR)/rtengine/Linux_x64
	else
		OPENSSL_LIBDIR = $(LIB_DIR)/openssl1.1._/Linux_x32
		RTENGINE_LIBDIR = $(LIB_DIR)/rtengine/Linux_x32
	endif
endif

ifneq (, $(findstring freebsd, ${ARCH}))
	ifneq (, $(findstring x86_64, ${ARCH}))
		OPENSSL_LIBDIR = $(LIB_DIR)/openssl1.1._/FreeBSD_x64
		RTENGINE_LIBDIR = $(LIB_DIR)/rtengine/FreeBSD_x64
	else
		OPENSSL_LIBDIR = $(LIB_DIR)/openssl1.1._/FreeBSD_x32
		RTENGINE_LIBDIR = $(LIB_DIR)/rtengine/FreeBSD_x32
	endif
endif

OUTDIR = ./../../../out/${platform}-${CONFIGURATION}

all: friendlyOpenSSL

friendlyOpenSSL:
	@echo "\n\n"$@" Building...\n\n"
	mkdir -p ${OUTDIR}
	$(CXX) ${CFLAGS} $(CXXFLAGS) -c \
	./*.cpp \
	-I$(INCLUDE_DIR)/openssl1.1._ -I$(INCLUDE_DIR)/rtengine/ -I$(INCLUDE_DIR)/StdPKCSh
	
	${AR} rcs ${OUTDIR}/friendlyOpenSSL.a  *.o
	rm ./*.o
	@echo "\n\n"$@" Done!\n\n"

CC=c++
CXXFLAGS=-ggdb -I/usr/local/boost_1_53_0

TEST_OBJS = IEncryptor.o \
            EncryptionSink.o \
            test.o 

.c.o:
	$(CC) -c $(CFLAGS) -arch x86_64 $*.cpp

all: test

test:  $(TEST_OBJS)
	$(CC) $(CFLAGS) -o $@ $(TEST_OBJS)

clean:
	/bin/rm -f *.o *~ test

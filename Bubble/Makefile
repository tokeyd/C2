Target = Bubble
INCLUDE =
DEFS = 
CFLAGS = -g ${DEFS} ${INCLUDE}
CC = gcc
LIB = 
SRC = $(wildcard *.c)
#OBJ = $(patsubst %.c,%.o,$(SRC))
$(Target):$(SRC)
	$(CC) $(CFLAGS) $^ -o $@ $(LIB)
.PHONY:
clean:
	rm -rf *.o $(Target)








#gcc编译生成.o文件用-小c

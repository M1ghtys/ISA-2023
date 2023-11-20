CC= g++
CFLAGS= -pedantic -Wall -g
LDFLAGS= -lm -lncurses -lpcap

SRC= $(shell find -name "*.cpp")
OBJ= $(addsuffix .o, $(basename $(SRC)))
DEP= $(OBJ:.o=.d)

all: dhcp-stats

-include $(DEP)

run: all
	@./dhcp-stats

dhcp-stats: $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ) $(LDFLAGS)

%.o: %.cpp
	$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

clean:
	find -name "*.o" -delete
	find -name "*.d" -delete
	rm dhcp-stats

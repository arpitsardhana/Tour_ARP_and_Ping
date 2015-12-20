CC = gcc

LIBS = -lpthread -lm -lc \
        /users/cse533/Stevens/unpv13e/libunp.a

FLAGS = -g3
CFLAGS = ${FLAGS} -I/users/cse533/Stevens/unpv13e/lib

all: tour_arpsingh arp_arpsingh

tour_arpsingh: get_hw_addrs.o utility.o tour.o tour_areq.o  
	${CC} ${FLAGS} -o tour_arpsingh tour.o utility.o get_hw_addrs.o tour_areq.o ${LIBS}
tour.o: tour.c
	${CC} ${CFLAGS} -c tour.c
tour_areq.o: tour_areq.c
	${CC} ${CFLAGS} -c tour_areq.c

arp_arpsingh: get_hw_addrs.o utility.o arp.o
	${CC} ${FLAGS} -o arp_arpsingh arp.o utility.o get_hw_addrs.o ${LIBS}
arp.o: arp.c
	${CC} ${CFLAGS} -c arp.c

utility.o: utility.c
	${CC} ${CFLAGS} -c utility.c
get_hw_addrs.o: get_hw_addrs.c
	${CC} ${CFLAGS} -c get_hw_addrs.c


 
clean:
	rm -rf tour_arpsingh tour.o utility.o get_hw_addrs.o tour_areq.o tour_util.o arp.o arp_arpsingh

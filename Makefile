CXX=g++

PLATFORM = `uname -p`
HERE=$(shell pwd)


CPPFLAGS= -O2 # -g
TARGET=ipt_geofence
LIBS=-ljsoncpp -lmaxminddb  -lnetfilter_queue -lnfnetlink -lpthread
OBJECTS = $(patsubst %.cpp, %.o, $(wildcard *.cpp))
HEADERS = $(wildcard *.h)

$(TARGET): $(OBJECTS)
	$(CXX) $(CPPFLAGS) $(OBJECTS) -o ipt_geofence $(LIBS)

%.o: %.cpp $(HEADERS) Makefile
	$(CXX) $(CPPFLAGS) -c $< -o $@


clean:
	/bin/rm -rf *~ *~ *.o $(TARGET)

cleanall: clean
	/bin/rm -rf config.h autom4te.cache/ config.* configure $* Makefile

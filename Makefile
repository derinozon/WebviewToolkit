#For Ubuntu Users run "sudo apt install webkit2gtk-4.0"

UNAME := $(shell uname)

CC = g++
CCV = -std=c++17

ifeq ($(UNAME), Linux)
LIB = `pkg-config --cflags --libs gtk+-3.0 webkit2gtk-4.0`
else ifeq ($(UNAME), Darwin)
LIB = -framework WebKit
else
LIB = -mwindows -L./dll/x64 -lwebview -lWebView2Loader
endif



webui: examples/Radio/radio.cpp wwtk.hpp
	$(CC) $(CCV) examples/Radio/radio.cpp $(LIB) -o examples/Radio/radio.out
	$(CC) $(CCV) examples/Browser/browser.cpp $(LIB) -o examples/Browser/browser.out

run:
	cd ./examples/Radio/ && ./radio.out

precompile: main.cpp wwtk.hpp
	$(CC) $(CCV) wwtk.hpp
	$(CC) $(CCV) main.cpp -include wwtk.hpp $(LIB) -o webui
#pip3 install quom
header:
	quom webui.h dist/webui.h 
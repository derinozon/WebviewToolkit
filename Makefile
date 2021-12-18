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



webui: examples/Radio/radio.cpp webviewtk.hpp
	$(CC) $(CCV) examples/Notebook/notebook.cpp $(LIB) -o examples/Notebook/notebook
#	$(CC) $(CCV) examples/Radio/radio.cpp $(LIB) -o examples/Radio/radio
#	$(CC) $(CCV) examples/Browser/browser.cpp $(LIB) -o examples/Browser/browser.out

run:
	cd ./examples/Notebook/ && ./notebook
#	cd ./examples/Radio/ && ./radio

precompile: main.cpp wwtk.hpp
	$(CC) $(CCV) wwtk.hpp
	$(CC) $(CCV) main.cpp -include wwtk.hpp $(LIB) -o webui
#pip3 install quom
header:
	mkdir -p dist
	quom webviewtk.hpp dist/webviewtk.hpp
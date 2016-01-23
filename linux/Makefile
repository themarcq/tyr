run: tyr.o
	gcc -o bin/tyr bin/tyr.o  `pkg-config --libs glib-2.0;pkg-config --libs gdk-pixbuf-2.0` -pthread -lssl -lcrypto -lqrencode -lnotify -lpng

tyr.o:
	gcc src/tyr.c  -c `pkg-config --cflags glib-2.0;pkg-config --cflags gdk-pixbuf-2.0` -o bin/tyr.o

debug: tyr.o-debug
	gcc -g -o bin/tyr bin/tyr.o  `pkg-config --libs glib-2.0;pkg-config --libs gdk-pixbuf-2.0` -pthread -lssl -lcrypto -lqrencode -lnotify -lpng

tyr.o-debug:
	gcc -g src/tyr.c  -c `pkg-config --cflags glib-2.0;pkg-config --cflags gdk-pixbuf-2.0` -o bin/tyr.o

clean:
	rm bin/*

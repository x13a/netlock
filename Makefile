prefix ?= /usr/local
exec_prefix ?= $(prefix)
sbindir ?= $(exec_prefix)/sbin
NAME := netlock
ADMINUID := 501
destdir := $(DESTDIR)$(sbindir)
dest := $(destdir)/$(NAME)

all: build

build:
	cargo build --locked --release --bins

cargo-install:
	cargo install --locked --path "."

cargo-uninstall:
	cargo uninstall --locked $(NAME)

installdirs:
	install -o $(ADMINUID) -g staff -d $(destdir)/

install: installdirs
	install -o root -g wheel -f uchg ./target/release/$(NAME) $(destdir)/

uninstall:
	chflags nouchg $(dest)
	rm -f $(dest)

clean:
	cargo clean

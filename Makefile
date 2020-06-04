PREFIX ?= /usr/local
SBINDIR ?= $(PREFIX)/sbin
NAME := netlock
DEST := $(SBINDIR)/$(NAME)

all: build

build:
	cargo build --locked --release --bins

cargo-install:
	cargo install --locked --path "."

cargo-uninstall:
	cargo uninstall --locked $(NAME)

install:
	install -o 501 -g staff -d $(SBINDIR)/
	install -o root -g wheel -f uchg ./target/release/$(NAME) $(SBINDIR)/

uninstall:
	chflags nouchg $(DEST)
	rm -f $(DEST)

clean:
	cargo clean

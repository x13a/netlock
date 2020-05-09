PREFIX ?= /usr/local
SBINDIR ?= $(PREFIX)/sbin
NAME := netlock

all: build

build:
	cargo build --locked --release --bins

cargo-install:
	cargo install --locked --path "."

cargo-uninstall:
	cargo uninstall --locked $(NAME)

install:
	install -d $(SBINDIR)/
	install ./target/release/$(NAME) $(SBINDIR)/

uninstall:
	rm -f $(SBINDIR)/$(NAME)

clean:
	cargo clean

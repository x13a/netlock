NAME        := netlock

prefix      ?= /usr/local
exec_prefix ?= $(prefix)
sbindir     ?= $(exec_prefix)/sbin

sbindestdir := $(DESTDIR)$(sbindir)

all: build

build:
	cargo build --locked --release --bins

cargo-install:
	cargo install --locked --path "."

cargo-uninstall:
	cargo uninstall --locked $(NAME)

installdirs:
	install -d $(sbindestdir)/

install: installdirs
	install ./target/release/$(NAME) $(sbindestdir)/

uninstall:
	rm -f $(sbindestdir)/$(NAME)

clean:
	cargo clean

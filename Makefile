HIGHLIGHT_THEME = kate

.PHONY: help all pdf html clean

help:
	@echo Choose one of: {pdf, html, all} and make with the target as argument or clean to clean auto generated files
	@echo
	@echo Examples:
	@echo "   make pdf (compiles to PDF format)"
	@echo "   make read (read the generated pdf)"
	@echo "   make clean (removes any generated files)"
	@echo "   make help (this message)"

all: pdf html

pdf: theonenote.pdf

html: theonenote.html

clean:
	@rm -f *.pdf *.html

%.pdf: src/%.md
	@echo Compiling PDF version of TheOneNote
	@pandoc --highlight-style ${HIGHLIGHT_THEME} -o $@ $^

%.html: src/%.md
	@echo Compiling HTML version of TheOneNote
	@pandoc --highlight-style ${HIGHLIGHT_THEME} -o $@ $^

read: theonenote.pdf
	zathura $<

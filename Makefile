HIGHLIGHT_THEME = kate

help:
	@echo Choose one of pdf or html and make with the target as argument or clean to clean auto generated files

all: pdf html

pdf: theonenote.pdf

html: theonenote.html

clean:
	@rm -f theonenote.pdf theonenote.html

%.pdf: src/%.md
	@echo Compiling PDF version of TheOneNote
	@pandoc --highlight-style ${HIGHLIGHT_THEME} -o $@ src/$*.md

%.html: src/%.md
	@echo Compiling HTML version of TheOneNote
	@pandoc --highlight-style ${HIGHLIGHT_THEME} -o $@ src/$*.md


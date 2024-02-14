
programs := $(wildcard examples/*.qcl)
circs := $(patsubst %.qcl,%.circ,$(programs))
qclcs := $(patsubst %.qcl,%.qclc,$(programs))
bristols := $(patsubst %.qcl,%.bristol,$(programs))
ssas := $(patsubst %.qcl,%.ssa,$(programs))
dots := $(patsubst %,%.dot,$(circs) $(qclcs) $(bristols) $(ssas))
svgs := $(patsubst %.dot,%.svg,$(dots))

generated_dots := $(wildcard examples/*.dot)
generated_svgs := $(patsubst %.dot,%.svg,$(generated_dots))

all: $(generated_svgs)

%.svg: %.dot
	dot -Tsvg $+ > $@

clean:
	@rm -f $(circs) $(qclcs) $(bristols) $(ssas) $(dots) $(svgs)

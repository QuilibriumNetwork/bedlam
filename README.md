# Bedlam

This project is a very heavy fork of Markku Rossi's
[MPCL](https://github.com/markkurossi/mpc) library and is in heavy development.

Directionally we differ on a few levels:
- larger subset of golang support (in particular, supporting receiver functions)
- fixed parser bugs
- integration with additional OT-based primitives
- built to slot into hypergraph execution
- embedded FS to QCL/primitive circuits
- support for more advanced OT primitives (currently disabled in public preview)

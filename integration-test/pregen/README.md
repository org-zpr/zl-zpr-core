# pregen - Generated Integration Test Files

Various files pre-generated for running the integration tests.


## How to compile the policies

Can use the incuded `Makefile`.

The Zode fixtures (`zodes*.bin2`) need a zplc that knows node links and
peer CNs (`zl-zpr-compiler` `feature/zodes`). `zodes-pair.bin2` and
`zodes-direct.bin2` (zl-zipline#254) were compiled with zplc 0.20.1 from
`feature/zodes` (697db65), the version `zodes.bin2` was compiled with.

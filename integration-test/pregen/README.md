# pregen - Generated Integration Test Files

Various files pre-generated for running the integration tests.


## How to compile the policies

Can use the incuded `Makefile`.

Every `.bin2` here needs zplc 0.21.x: the visa service loads no other
policy version (zl-zipline#256). The Zode fixtures (`zodes*.bin2`) also
need a zplc that knows node links and peer CNs (`zl-zpr-compiler`
`feature/zodes`). Like every other fixture, `zodes-pair.bin2` and
`zodes-direct.bin2` (zl-zipline#254) were compiled with zpc 0.21.0
(v0.18.1-24-gefaaf38, tree-identical to compiler `feature/zodes` 3e16a94).
`zodes-login.bin2` (zl-zipline#233) was compiled with zpc 0.21.0
(v0.18.1-23-g3e16a94, compiler `feature/zodes`).
`attr-query.bin2` and the `zodes-policy-reauth*.bin2` fixtures
(zl-zipline#234) were compiled with zpc 0.21.0 (v0.18.1-23-g3e16a94,
compiler `feature/zodes`).
`zodes-ping.bin2` (zl-zipline#234) was compiled with zpc 0.21.0
(v0.18.1-23-g3e16a94, compiler `feature/zodes`).

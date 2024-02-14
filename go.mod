module source.quilibrium.com/quilibrium/monorepo/bedlam

go 1.20

// A necessary hack until source.quilibrium.com is open to all
replace source.quilibrium.com/quilibrium/monorepo/nekryptology => ../nekryptology

require (
	github.com/btcsuite/btcd/btcec/v2 v2.3.2
	source.quilibrium.com/quilibrium/monorepo/nekryptology v0.0.0-00010101000000-000000000000
)

require github.com/pkg/errors v0.9.1 // indirect

require (
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.0.1 // indirect
	golang.org/x/exp v0.0.0-20231006140011-7918f672742d
)

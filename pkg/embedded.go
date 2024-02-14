package pkg

import "embed"

//go:embed bits/*
//go:embed bytes/*
//go:embed crypto/*
//go:embed encoding/*
//go:embed math/*
//go:embed sort/*
//go:embed builtin.qcl
var PkgFS embed.FS

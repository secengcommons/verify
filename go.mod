module github.com/secengcommons/verify

go 1.26.0
toolchain go1.27.2

require (
	github.com/secengcommons/cli v1.1.1
	github.com/secengcommons/proctree v1.1.1
	go.yaml.in/yaml/v3 v3.0.5
	golang.org/x/mod v0.42.0
	golang.org/x/sys v0.49.0
)

// Abandoned test releases
retract (
	v0.2.1
	v0.2.0
	v0.1.1
	v0.1.0
)

module github.com/secengcommons/verify

go 1.25.0
toolchain go1.27.1

require (
	github.com/secengcommons/cli v1.0.0
	github.com/secengcommons/proctree v1.0.0
	go.yaml.in/yaml/v3 v3.0.5
	golang.org/x/mod v0.40.0
	golang.org/x/sys v0.47.0
)

// Abandoned test releases
retract (
	v0.2.1
	v0.2.0
	v0.1.1
	v0.1.0
)

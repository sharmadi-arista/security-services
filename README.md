# Openconfig Security Services

## SBOM

### CLI

#### Overview

The SBOM CLI tool allows for validation and conversion of SBOM from external sources into the SPDX standard format.
The current formats supported are input in SPDX 2.3 and Cyclone DX 1.6 proto and JSON. These formats will then be validated against an SBOM conformance tool.

SBOM are used to convey the software manifest of a package including a dependencies.  The [NTIA](https://www.ntia.gov/page/software-bill-materials) defines two major formats for SBOMs, SPDX and CycloneDX.  The SBOM CLI will support both formats for conversion and conformance check to OpenConfig SBOM format.

#### Build

* `go build -o sbom_cli cli/main.go`

#### Examples

* Convert CycloneDX 1.6 JSON to SPDX 2.3

```shell
./sbom_cli convert ./cyclonedx.json ./spdx.json --format=cyclonedx-v16-json
```

* Convert and Validate CycloneDX 1.6 JSON to SPDX 2.3

```shell
./sbom_cli convert ./cyclonedx.json ./spdx.json --format=cyclonedx-v16-json --validate
```

* Convert and Validate CycloneDX 1.6 PROTO to SPDX 2.3

```shell
./sbom_cli convert ./cyclonedx.json ./spdx.json --format=cyclonedx-v16-proto --validate
```

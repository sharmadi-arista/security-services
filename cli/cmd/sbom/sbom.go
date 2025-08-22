package sbom

import (
	"encoding/json"
	"fmt"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/spdx/v2/common"
	"github.com/spdx/tools-golang/spdx/v2/v2_3"
	log "k8s.io/klog"
)

func ConvertToGoogleSPDX(bom *cdx.BOM) (*spdx.Document, error) {
	spdxDoc := spdx.Document{
		DocumentName:      bom.Metadata.Component.Name,
		DocumentNamespace: "", // This needs to be a PURL?
		SPDXVersion:       spdx.Version,
		DataLicense:       "CC0-1.0",
		CreationInfo: &v2_3.CreationInfo{
			Created: bom.Metadata.Timestamp,
			Creators: []common.Creator{{
				Creator:     bom.Metadata.Component.Supplier.Name,
				CreatorType: "Organization",
			}},
		},
		SPDXIdentifier: "SPDXRef-DOCUMENT",
	}

	refMap := map[string]cdx.Component{}
	typeMap := map[string]int{}
	for _, c := range *bom.Components {
		if _, ok := refMap[c.BOMRef]; ok {
			return nil, fmt.Errorf("duplicate BOM ref: %q", c.BOMRef)
		}
		refMap[c.BOMRef] = c
		typeMap[string(c.Type)] += 1
		if c.Type == "library" {
			p := &spdx.Package{
				PackageName:        c.Name,
				PackageVersion:     c.Version,
				PackageDescription: c.Description,
			}
			validIdentifier := false
			if c.PackageURL != "" {
				p.PackageExternalReferences = append(p.PackageExternalReferences, &spdx.PackageExternalReference{
					Category: "SECURITY",
					Locator:  c.PackageURL,
					RefType:  "purl",
				})
				validIdentifier = true
			}
			if c.CPE != "" {
				p.PackageExternalReferences = append(p.PackageExternalReferences, &spdx.PackageExternalReference{
					Category: "SECURITY",
					Locator:  c.CPE,
					RefType:  "cpe22Type",
				})
				validIdentifier = true
			}
			if !validIdentifier {
				log.Warningf("package %q:%q:%q missing PURL and CPE", c.Name, c.Type, c.MIMEType)
			}
			spdxDoc.Packages = append(spdxDoc.Packages, p)
		}
	}

	compTypeMap := map[string]int{}
	assemblyDAG := map[string][]string{}
	asmRefErr := 0
	for _, c := range *bom.Compositions {
		compType := "unknown"
		switch {
		case len(*c.Assemblies) != 0:
			compType = "assembly"
			// Let's parse the assembly
			asmKey := string((*c.Assemblies)[0])
			if _, ok := refMap[asmKey]; !ok {
				asmRefErr++
			}
			v := assemblyDAG[asmKey]
			for _, asm := range (*c.Assemblies)[1:] {
				v = append(v, string(asm))
			}
		case len(*c.Dependencies) != 0:
			compType = "dependency"
		case len(*c.Vulnerabilities) != 0:
			compType = "vulnerability"
		}
		compTypeMap[compType] += 1
		if c.BOMRef != "" {
			log.Infof("compos: %q", c.BOMRef)
		}
	}
	log.Infof("Found %d Assembly ref errors", asmRefErr)
	refErrs := 0
	log.Infof("Loaded %d components from BOM", len(refMap))
	log.Infof("building SBOM map")
	for _, rm := range *bom.Dependencies {
		c, ok := refMap[rm.Ref]
		if !ok {
			refErrs++
			log.V(1).Infof("missing component ref: %q", rm.Ref)
			continue
			// return "", fmt.Errorf("missing component ref: %q", rm.Ref)
		}
		log.V(1).Infof("building deps for component %q", c.Name)
		var deps []string
		for _, depRef := range *rm.Dependencies {
			r, ok := refMap[depRef]
			if !ok {
				log.V(1).Infof("missing dep component ref: %q", rm.Ref)
			}
			deps = append(deps, r.Name)
		}
		log.V(1).Infof("%q: %q", c.Name, deps)
	}
	log.Infof("SBOM map ref errs: %d", refErrs)
	log.Infof("TypeMap: %+v", typeMap)
	log.Infof("CompMap: %+v", compTypeMap)
	return &spdxDoc, nil
}

func SPDXToJSON(spdxDoc *spdx.Document) ([]byte, error) {
	return json.MarshalIndent(spdxDoc, "", " ")
}

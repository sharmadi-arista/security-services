package sbom

import (
	"encoding/json"
	"fmt"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/spdx/tools-golang/spdx"
	log "k8s.io/klog"
)

func ConvertToGoogleSPDX(bom *cdx.BOM) (string, error) {
	spdxDoc := spdx.Document{}
	spdxDoc.DocumentName = bom.Metadata.Component.Name
	refMap := map[string]cdx.Component{}
	typeMap := map[string]int{}
	for _, c := range *bom.Components {
		if _, ok := refMap[c.BOMRef]; ok {
			return "", fmt.Errorf("duplicate BOM ref: %q", c.BOMRef)
		}
		typeMap[string(c.Type)] += 1
		if c.Type == "library" {
			refMap[c.BOMRef] = c
			p := &spdx.Package{
				PackageName:        c.Name,
				PackageVersion:     c.Version,
				PackageDescription: c.Description,
			}
			if c.PackageURL != "" {
				p.PackageExternalReferences = append(p.PackageExternalReferences, &spdx.PackageExternalReference{
					Category: "SECURITY",
					Locator:  c.PackageURL,
					RefType:  "purl",
				})
			}
			if c.CPE != "" {
				p.PackageExternalReferences = append(p.PackageExternalReferences, &spdx.PackageExternalReference{
					Category: "SECURITY",
					Locator:  c.CPE,
					RefType:  "cpe22Type",
				})
			}
			spdxDoc.Packages = append(spdxDoc.Packages, p)
		}
	}

	for _, c := range *bom.Compositions {
		if c.BOMRef != "" {
			log.Infof("compos: %q", c.BOMRef)
		}
	}
	refErrs := 0
	log.Infof("Loaded %d components from BOM", len(refMap))
	log.Infof("building SBOM map")
	for _, rm := range *bom.Dependencies {
		c, ok := refMap[rm.Ref]
		if !ok {
			refErrs++
			log.Warningf("missing component ref: %q", rm.Ref)
			continue
			// return "", fmt.Errorf("missing component ref: %q", rm.Ref)
		}
		log.Infof("building deps for component %q", c.Name)
		var deps []string
		for _, depRef := range *rm.Dependencies {
			r, ok := refMap[depRef]
			if !ok {
				log.Warningf("missing component ref: %q", rm.Ref)
			}
			deps = append(deps, r.Name)
		}
		log.Infof("%q: %q", c.Name, deps)
	}
	log.Infof("SBOM map ref errs: %d", refErrs)
	b, err := json.MarshalIndent(spdxDoc, "", "  ")
	if err != nil {
		return "", err
	}
	log.Infof("TypeMap: %+v", typeMap)
	return string(b), nil
}

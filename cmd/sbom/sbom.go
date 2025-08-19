package sbom

import (
	"fmt"

	cdx "github.com/CycloneDX/cyclonedx-go"
	log "k8s.io/klog"
)

func ConvertToGoogleSPDX(bom *cdx.BOM) (string, error) {
	refMap := map[string]cdx.Component{}
	for _, c := range *bom.Components {
		if _, ok := refMap[c.BOMRef]; ok {
			return "", fmt.Errorf("duplicate BOM ref: %q", c.BOMRef)
		}
		refMap[c.BOMRef] = c
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
	return "", nil
}

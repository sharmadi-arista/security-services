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
		SPDXIdentifier: toSPDXElementID("DOCUMENT"),
	}

	refMap := map[string]cdx.Component{}
	typeMap := map[string]int{}

	if bom.Metadata != nil && bom.Metadata.Component != nil {
		if err := AddCycloneDXComponent(
			*bom.Metadata.Component,
			refMap,
			typeMap,
			&spdxDoc,
		); err != nil {
			return nil, fmt.Errorf("failed to add metadata component: %w", err)
		}
	}

	if bom.Components != nil {
		for _, component := range *bom.Components {
			if err := AddCycloneDXComponent(component, refMap, typeMap, &spdxDoc); err != nil {
				return nil, fmt.Errorf("failed to add component %q: %w", component.BOMRef, err)
			}
		}
	}

	// Add CycloneDX dependencies to SPDX.
	if bom.Dependencies != nil {
		for _, deps := range *bom.Dependencies {
			if err := AddCycloneDXDependencies(deps, refMap, &spdxDoc); err != nil {
				return nil, fmt.Errorf("failed to add dependencies for ref %q: %w",
					deps.Ref, err)
			}
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
	log.Infof("Loaded %d components from BOM", len(refMap))
	log.Infof("TypeMap: %+v", typeMap)
	log.Infof("CompMap: %+v", compTypeMap)
	return &spdxDoc, nil
}

func SPDXToJSON(spdxDoc *spdx.Document) ([]byte, error) {
	return json.MarshalIndent(spdxDoc, "", " ")
}

func AddCycloneDXComponent(
	c cdx.Component,
	refMap map[string]cdx.Component,
	typeMap map[string]int,
	spdxDoc *spdx.Document,
) error {
	if _, ok := refMap[c.BOMRef]; ok {
		return fmt.Errorf("duplicate BOM ref: %q", c.BOMRef)
	}

	refMap[c.BOMRef] = c
	typeMap[string(c.Type)] += 1

	if IsComponentSPDXPackage(c) {
		p := &spdx.Package{
			PackageSPDXIdentifier: toSPDXElementID(c.BOMRef),
			PackageName:           c.Name,
			PackageVersion:        c.Version,
			PackageDescription:    c.Description,
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

		// Add supplier information.
		if c.Supplier != nil {
			p.PackageSupplier = &common.Supplier{
				Supplier:     c.Supplier.Name,
				SupplierType: "NOASSERTION",
			}
		}

		// Add package download location.
		if c.ExternalReferences != nil {
			for _, eRef := range *c.ExternalReferences {
				if eRef.Type == cdx.ERTypeDistribution {
					p.PackageDownloadLocation = eRef.URL
				}
			}
		}
		if p.PackageDownloadLocation == "" {
			p.PackageDownloadLocation = "NOASSERTION"
		}

		spdxDoc.Packages = append(spdxDoc.Packages, p)
	}

	// Add nested components.
	if c.Components != nil {
		for _, subComponent := range *c.Components {
			err := AddCycloneDXComponent(subComponent, refMap, typeMap, spdxDoc)
			if err != nil {
				return fmt.Errorf("failed to add sub-component %q: %w", subComponent.BOMRef, err)
			}
			// Add contained components with SPDX "CONTAINS" relationships.
			spdxDoc.Relationships = append(spdxDoc.Relationships, &v2_3.Relationship{
				RefA:         toSPDXDocElementID(c.BOMRef),
				RefB:         toSPDXDocElementID(subComponent.BOMRef),
				Relationship: "CONTAINS",
			})
		}
	}

	return nil
}

// AddCycloneDXDependencies maps CycloneDX dependencies to SPDX "DEPENDS_ON" relationships.
func AddCycloneDXDependencies(
	dependency cdx.Dependency,
	refMap map[string]cdx.Component,
	spdxDoc *spdx.Document,
) error {
	compA, exists := refMap[dependency.Ref]
	if !exists {
		return fmt.Errorf("missing reference in cdx.components: %q",
			dependency.Ref)
	}

	if dependency.Dependencies == nil {
		return nil // No dependencies to map
	}

	for _, depRef := range *dependency.Dependencies {
		compB, exists := refMap[depRef]
		if !exists {
			return fmt.Errorf("missing dependency reference in cdx.components: %q",
				depRef)
		}

		spdxDoc.Relationships = append(spdxDoc.Relationships, &v2_3.Relationship{
			RefA:         toSPDXDocElementID(compA.BOMRef),
			RefB:         toSPDXDocElementID(compB.BOMRef),
			Relationship: "DEPENDS_ON",
		})
	}

	return nil
}

// ========== Helper methods =============

func toSPDXDocElementID(bomRef string) common.DocElementID {
	return common.DocElementID{
		ElementRefID: toSPDXElementID(bomRef),
	}
}

func toSPDXElementID(bomRef string) common.ElementID {
	return common.ElementID(fmt.Sprintf("SPDXRef-%s", bomRef))
}

func IsComponentSPDXPackage(component cdx.Component) bool {
	// Keeping it as switch, as we might need to add more cdx component types.
	switch component.Type {
	case cdx.ComponentTypeLibrary:
		return true
	default:
		return false
	}
}

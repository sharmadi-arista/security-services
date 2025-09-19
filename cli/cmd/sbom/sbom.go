package sbom

import (
	"encoding/json"
	"fmt"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/spdx/v2/common"
	"github.com/spdx/tools-golang/spdx/v2/v2_3"
	log "k8s.io/klog"
)

func ConvertToGoogleSPDX(bom *cdx.BOM) (*spdx.Document, error) {
	spdxDoc := spdx.Document{
		SPDXVersion:    spdx.Version,
		DataLicense:    "CC0-1.0",
		SPDXIdentifier: toSPDXElementID("DOCUMENT"),
	}

	refMap := map[string]cdx.Component{}
	typeMap := map[string]int{}

	if bom.Metadata != nil {
		spdxDoc.CreationInfo = &v2_3.CreationInfo{
			Created: bom.Metadata.Timestamp,
		}
		if bom.Metadata.Component != nil {
			metaComp := bom.Metadata.Component
			spdxDoc.DocumentName = metaComp.Name
			if metaComp.Supplier != nil {
				spdxDoc.CreationInfo.Creators = []common.Creator{{
					Creator:     metaComp.Supplier.Name,
					CreatorType: "Organization",
				}}
			}
			if err := AddCycloneDXComponent(
				*metaComp,
				refMap,
				typeMap,
				&spdxDoc,
			); err != nil {
				return nil, fmt.Errorf("failed to add metadata component: %w", err)
			}
		}
	}

	// Build SPDX document namespace.
	if spdxDoc.DocumentNamespace == "" {
		serialNumber := strings.TrimPrefix(bom.SerialNumber, "urn:uuid:")
		if serialNumber != "" && spdxDoc.DocumentName != "" {
			spdxDoc.DocumentNamespace = fmt.Sprintf("http://spdx.org/spdxdocs/%s-%s",
				spdxDoc.DocumentName, serialNumber)
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

	log.Infof("Loaded %d components from BOM", len(refMap))
	log.Infof("TypeMap: %+v", typeMap)
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

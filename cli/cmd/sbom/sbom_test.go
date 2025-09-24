package sbom

import (
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/spdx/v2/v2_3"
	"github.com/stretchr/testify/assert"
)

func TestAddCycloneDXComponents(t *testing.T) {
	t.Run("should add component to maps and create SPDX package", func(t *testing.T) {
		refMap := make(map[string]cdx.Component)
		typeMap := make(map[string]int)
		spdxDoc := &spdx.Document{}

		component := cdx.Component{
			BOMRef:      "test-ref",
			Type:        cdx.ComponentTypeLibrary,
			Name:        "test-component",
			Version:     "1.0.0",
			Description: "Test component",
			PackageURL:  "pkg:npm/test@1.0.0",
		}

		err := AddCycloneDXComponent(component, refMap, typeMap, spdxDoc)

		if err != nil {
			t.Errorf("AddCycloneDXComponents() error = %v, want nil", err)
		}

		// Check refMap
		if _, ok := refMap["test-ref"]; !ok {
			t.Error("Component not added to refMap")
		}

		// Check typeMap
		if typeMap["library"] != 1 {
			t.Errorf("typeMap[library] = %d, want 1", typeMap["library"])
		}

		// Check SPDX package created
		if len(spdxDoc.Packages) != 1 {
			t.Errorf("Expected 1 package, got %d", len(spdxDoc.Packages))
		}
	})

	t.Run("should return error for duplicate BOM ref", func(t *testing.T) {
		refMap := map[string]cdx.Component{
			"duplicate-ref": {BOMRef: "duplicate-ref"},
		}
		typeMap := make(map[string]int)
		spdxDoc := &spdx.Document{}

		component := cdx.Component{
			BOMRef: "duplicate-ref",
			Type:   cdx.ComponentTypeLibrary,
		}

		err := AddCycloneDXComponent(component, refMap, typeMap, spdxDoc)

		if err == nil {
			t.Error("Expected error for duplicate BOM ref, got nil")
		}
		if !strings.Contains(err.Error(), "duplicate BOM ref") {
			t.Errorf("Error message should contain 'duplicate BOM ref', got: %v", err)
		}
	})

	t.Run("should not create SPDX package for non-package component", func(t *testing.T) {
		refMap := make(map[string]cdx.Component)
		typeMap := make(map[string]int)
		spdxDoc := &spdx.Document{}

		component := cdx.Component{
			BOMRef: "file-ref",
			Type:   cdx.ComponentTypeFile,
			Name:   "test-file",
		}

		err := AddCycloneDXComponent(component, refMap, typeMap, spdxDoc)

		if err != nil {
			t.Errorf("AddCycloneDXComponents() error = %v, want nil", err)
		}

		// Should still be added to maps
		if _, ok := refMap["file-ref"]; !ok {
			t.Error("Component not added to refMap")
		}

		// Should not create SPDX package
		if len(spdxDoc.Packages) != 0 {
			t.Errorf("Expected 0 packages for file component, got %d", len(spdxDoc.Packages))
		}
	})

	t.Run("should handle component with both PURL and CPE", func(t *testing.T) {
		refMap := make(map[string]cdx.Component)
		typeMap := make(map[string]int)
		spdxDoc := &spdx.Document{}

		emptyComponents := &[]cdx.Component{}
		component := cdx.Component{
			BOMRef:     "test-ref",
			Type:       cdx.ComponentTypeLibrary,
			Name:       "test-component",
			PackageURL: "pkg:npm/test@1.0.0",
			CPE:        "cpe:2.3:a:example:test:1.0.0:*:*:*:*:*:*:*",
			Components: emptyComponents,
		}

		err := AddCycloneDXComponent(component, refMap, typeMap, spdxDoc)

		if err != nil {
			t.Errorf("AddCycloneDXComponents() error = %v, want nil", err)
		}

		// Check external references
		if len(spdxDoc.Packages) != 1 {
			t.Fatalf("Expected 1 package, got %d", len(spdxDoc.Packages))
		}

		pkg := spdxDoc.Packages[0]
		if len(pkg.PackageExternalReferences) != 2 {
			t.Errorf("Expected 2 external references, got %d", len(pkg.PackageExternalReferences))
		}
	})

	t.Run("Test component with supplier information", func(t *testing.T) {
		refMap := make(map[string]cdx.Component)
		typeMap := make(map[string]int)
		spdxDoc := &spdx.Document{}

		emptyComponents := &[]cdx.Component{}
		component := cdx.Component{
			BOMRef: "test-ref",
			Type:   cdx.ComponentTypeLibrary,
			Name:   "test-component",
			Supplier: &cdx.OrganizationalEntity{
				Name: "test-supplier",
			},
			Components: emptyComponents,
		}

		err := AddCycloneDXComponent(component, refMap, typeMap, spdxDoc)

		if err != nil {
			t.Errorf("AddCycloneDXComponents() error = %v, want nil", err)
		}

		if len(spdxDoc.Packages) != 1 {
			t.Fatalf("Expected 1 package, got %d", len(spdxDoc.Packages))
		}

		// Check package supplier information.
		pkg := spdxDoc.Packages[0]
		if pkg.PackageSupplier == nil {
			t.Fatalf("Package supplier must be set")
		}

		if pkg.PackageSupplier.Supplier != component.Supplier.Name {
			t.Fatalf("Expected package supplier to be %q, got %q",
				component.Supplier.Name, pkg.PackageSupplier.Supplier)
		}

		if pkg.PackageSupplier.SupplierType != "NOASSERTION" {
			t.Fatalf("Expected package supplier type to be NOASSERTION, got %q",
				pkg.PackageSupplier.SupplierType)
		}
	})

	t.Run("Test component with download location", func(t *testing.T) {
		refMap := make(map[string]cdx.Component)
		typeMap := make(map[string]int)
		spdxDoc := &spdx.Document{}
		pkgDownloadLocation := "http://downlaodlink"
		emptyComponents := &[]cdx.Component{}
		component := cdx.Component{
			BOMRef: "test-ref",
			Type:   cdx.ComponentTypeLibrary,
			Name:   "test-component",
			ExternalReferences: &[]cdx.ExternalReference{
				{
					Type: cdx.ERTypeDistribution,
					URL:  pkgDownloadLocation,
				},
			},
			Components: emptyComponents,
		}

		err := AddCycloneDXComponent(component, refMap, typeMap, spdxDoc)

		if err != nil {
			t.Errorf("AddCycloneDXComponents() error = %v, want nil", err)
		}

		// Check package download location.
		pkg := spdxDoc.Packages[0]
		if pkg.PackageDownloadLocation != pkgDownloadLocation {
			t.Fatalf("Expected package download location to be %s, got %s",
				pkgDownloadLocation, pkg.PackageDownloadLocation)
		}
	})

	t.Run("Test component with contain relationships", func(t *testing.T) {
		refMap := make(map[string]cdx.Component)
		typeMap := make(map[string]int)
		spdxDoc := &spdx.Document{}
		refA := "test-refA"
		refB := "test-refB"
		component := cdx.Component{
			BOMRef: refA,
			Type:   cdx.ComponentTypeLibrary,
			Name:   "test-componentA",
			Components: &[]cdx.Component{
				{
					BOMRef: refB,
					Type:   cdx.ComponentTypeLibrary,
					Name:   "test-componentB",
				},
			},
		}

		err := AddCycloneDXComponent(component, refMap, typeMap, spdxDoc)
		if err != nil {
			t.Errorf("AddCycloneDXComponents() error = %v, want nil", err)
		}

		// Check contain relationship.
		if len(spdxDoc.Packages) != 2 {
			t.Fatalf("Expected 2 packages, got %d", len(spdxDoc.Packages))
		}

		relations := spdxDoc.Relationships
		if len(relations) != 1 {
			t.Fatalf("Expected 1 relationship, got %d", len(relations))
		}

		relation := relations[0]
		if relation.Relationship != "CONTAINS" {
			t.Fatalf("Expected relationship of type CONTAINS, got %q", relation.Relationship)
		}
		if relation.RefA != toSPDXDocElementID(refA) {
			t.Fatalf("Expected relation.refA to be %q, got %q", toSPDXElementID(refA), relation.RefA)
		}
		if relation.RefB != toSPDXDocElementID(refB) {
			t.Fatalf("Expected relation.refB to be %q, got %q", toSPDXElementID(refB), relation.RefB)
		}
	})
}

func TestAddCycloneDXDependencies(t *testing.T) {
	tests := []struct {
		name         string
		dependency   cdx.Dependency
		componentMap map[string]cdx.Component
		expectedErr  string
		expectedRels []*v2_3.Relationship
	}{
		{
			name: "success with one dependency",
			dependency: cdx.Dependency{
				Ref:          "componentA",
				Dependencies: &[]string{"componentB"},
			},
			componentMap: map[string]cdx.Component{
				"componentA": {BOMRef: "componentA"},
				"componentB": {BOMRef: "componentB"},
			},
			expectedErr: "",
			expectedRels: []*v2_3.Relationship{
				{
					RefA:         toSPDXDocElementID("componentA"),
					RefB:         toSPDXDocElementID("componentB"),
					Relationship: "DEPENDS_ON",
				},
			},
		},
		{
			name: "missing source component",
			dependency: cdx.Dependency{
				Ref:          "missingComponent",
				Dependencies: &[]string{"componentB"},
			},
			componentMap: map[string]cdx.Component{
				"componentB": {BOMRef: "componentB"},
			},
			expectedErr:  `missing reference in cdx.components: "missingComponent"`,
			expectedRels: nil,
		},
		{
			name: "missing dependency component",
			dependency: cdx.Dependency{
				Ref:          "componentA",
				Dependencies: &[]string{"missingDep"},
			},
			componentMap: map[string]cdx.Component{
				"componentA": {BOMRef: "componentA"},
			},
			expectedErr:  `missing dependency reference in cdx.components: "missingDep"`,
			expectedRels: nil,
		},
		{
			name: "no dependencies",
			dependency: cdx.Dependency{
				Ref:          "componentA",
				Dependencies: nil,
			},
			componentMap: map[string]cdx.Component{
				"componentA": {BOMRef: "componentA"},
			},
			expectedErr:  "",
			expectedRels: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doc := &v2_3.Document{}

			err := AddCycloneDXDependencies(tc.dependency, tc.componentMap, doc)

			if tc.expectedErr != "" {
				assert.EqualError(t, err, tc.expectedErr)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedRels, doc.Relationships)
			}
		})
	}
}

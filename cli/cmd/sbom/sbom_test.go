package sbom

import (
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/spdx/tools-golang/spdx"
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
}

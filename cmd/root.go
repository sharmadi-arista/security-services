// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	"github.com/openconfig/security-services/cmd/sbom"
	"github.com/spf13/cobra"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

func New() *cobra.Command {
	root := &cobra.Command{
		Use:          "sbom",
		Short:        "SBOM management",
		Long:         `Manage SBOMs including conversion utilities.`,
		SilenceUsage: true,
	}
	root.SetOut(os.Stdout)
	root.AddCommand(newShowCmd())
	root.AddCommand(newConvertCmd())
	return root
}

func newShowCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "show <SBOM file name>",
		Short: "show <SBOM file name>",
		RunE:  showSBOM,
	}
	cmd.Flags().String("format", "cyclonedx-v16-proto", "Format of the SBOM")
	return cmd
}

func newConvertCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "convert <SBOM file name>",
		Short: "convert <SBOM file name>",
		RunE:  convertSBOM,
	}
	cmd.Flags().String("format", "cyclonedx-v16-proto", "Format of the SBOM")
	return cmd
}

func showSBOM(cmd *cobra.Command, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("SBOM arg required")
	}
	sbomFileName := args[0]
	format, err := cmd.Flags().GetString("format")
	if err != nil {
		return err
	}
	switch format {
	case "cyclonedx-v16-proto":
		return fmt.Errorf("unimplemented format: cyclonedx-v16-proto")
	case "cyclonedx-v16-json":
		sbom, err := loadCycloneDXJSON(sbomFileName)
		if err != nil {
			return err
		}
		b, err := printCycloneDX(sbom)
		if err != nil {
			return err
		}
		fmt.Fprintln(cmd.OutOrStderr(), "SBOM:")
		fmt.Fprintln(cmd.OutOrStdout(), string(b))
		return nil

	case "spdx-v23-json":
		return fmt.Errorf("unimplemented format: spdx-v23-json")
	}
	return fmt.Errorf("Invalid format: %q", format)
}

func loadCycloneDXJSON(filename string) (*cdx.BOM, error) {
	b, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	d := cdx.NewBOMDecoder(bytes.NewBuffer(b), cdx.BOMFileFormatJSON)
	bom := cdx.NewBOM()
	if err := d.Decode(bom); err != nil {
		return nil, err
	}
	fmt.Println(bom)
	return bom, nil
}

func printCycloneDX(sbom *cdx.BOM) ([]byte, error) {
	return json.MarshalIndent(sbom, "", "  ")
}

func convertSBOM(cmd *cobra.Command, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("SBOM arg required")
	}
	sbomFileName := args[0]
	format, err := cmd.Flags().GetString("format")
	if err != nil {
		return err
	}
	switch format {
	case "cyclonedx-v16-proto":
		return fmt.Errorf("unimplemented format: cyclonedx-v16-proto")
	case "cyclonedx-v16-json":
		bom, err := loadCycloneDXJSON(sbomFileName)
		if err != nil {
			return err
		}
		s, err := sbom.ConvertToGoogleSPDX(bom)
		if err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "SPDX:\n%s\n", s)
		return nil

	case "spdx-v23-json":
		return fmt.Errorf("unimplemented format: spdx-v23-json")
	}
	return fmt.Errorf("Invalid format: %q", format)
}

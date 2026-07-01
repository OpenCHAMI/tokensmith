// Copyright © 2025 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/openchami/fabrica/pkg/annotations"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <go-file>\n", os.Args[0])
		os.Exit(1)
	}

	filename := os.Args[1]

	// Parse annotations from file
	anns, err := annotations.ParseFileAnnotations(filename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing annotations: %v\n", err)
		os.Exit(1)
	}

	// Pretty-print results
	data, err := json.MarshalIndent(anns, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling JSON: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(string(data))
}

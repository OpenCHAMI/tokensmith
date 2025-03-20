package main

import (
	"fmt"
	"os"

	tokenservice "github.com/openchami/tokensmith/pkg/tokenservice"
	"github.com/spf13/cobra"
)

var (
	providerType  string
	issuer        string
	port          int
	clusterID     string
	openCHAMIID   string
	hydraURL      string
	autheliaURL   string
	keycloakURL   string
	keycloakRealm string
	configPath    string
	keyFile       string
	keyDir        string
)

var rootCmd = &cobra.Command{
	Use:   "tokensmith",
	Short: "TokenSmith - Token Exchange Service",
	Long:  `TokenSmith provides token exchange and validation services for OpenCHAMI.`,
}

var generateConfigCmd = &cobra.Command{
	Use:   "generate-config",
	Short: "Generate a default configuration file",
	RunE: func(cmd *cobra.Command, args []string) error {
		config := tokenservice.DefaultFileConfig()
		if err := tokenservice.SaveFileConfig(config, configPath); err != nil {
			return fmt.Errorf("failed to save config: %w", err)
		}
		fmt.Printf("Generated configuration file at: %s\n", configPath)
		return nil
	},
}

func init() {

	rootCmd.AddCommand(generateConfigCmd)

	// Global flags
	rootCmd.PersistentFlags().StringVar(&configPath, "config", "", "Path to configuration file")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "single-login",
	Short: "JWT Authentication CLI using JWKs",
	Long:  `A CLI application for JWT authentication using JSON Web Key Sets (JWKS)`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

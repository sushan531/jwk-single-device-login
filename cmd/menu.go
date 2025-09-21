package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/sushan531/jwkauth/internal/database"
	"github.com/sushan531/jwkauth/internal/manager"
	"github.com/sushan531/jwkauth/model"
	"github.com/sushan531/jwkauth/service"
)

var (
	dbType      string
	dbPath      string
	dbConnStr   string
)

var menuCmd = &cobra.Command{
	Use:   "menu",
	Short: "Interactive menu for JWT operations",
	Run:   runMenu,
}

func init() {
	rootCmd.AddCommand(menuCmd)
	
	// Add flags for database configuration
	menuCmd.Flags().StringVar(&dbType, "db-type", "sqlite", "Database type (sqlite or postgres)")
	menuCmd.Flags().StringVar(&dbPath, "db-path", "jwk_keys.db", "Path to SQLite database file")
	menuCmd.Flags().StringVar(&dbConnStr, "db-conn", "", "PostgreSQL connection string (e.g., postgres://user:password@localhost/dbname?sslmode=disable)")
}

func runMenu(cmd *cobra.Command, args []string) {
	// Configure database based on flags
	dbConfig := database.Config{
		DBType:    database.DBType(dbType),
		DBPath:    dbPath,
		DBConnStr: dbConnStr,
	}
	
	// Validate configuration
	if dbConfig.DBType == database.PostgreSQL && dbConfig.DBConnStr == "" {
		fmt.Println("Error: PostgreSQL connection string is required when using postgres database type")
		fmt.Println("Example: --db-conn=\"postgres://user:password@localhost/dbname?sslmode=disable\"")
		return
	}

	var jwkManager = manager.NewJwkManager(manager.JwkManagerConfig{
		DBConfig: dbConfig,
	})
	
	var jwtManager = manager.NewJwtManager(jwkManager, manager.JwtManagerConfig{
		TokenExpiration: 2400 * time.Hour,
	})
	
	var authService = service.NewAuthService(jwtManager, jwkManager)

	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Println("\nJWT Authentication Menu:")
		fmt.Println("1. Generate Token")
		fmt.Println("2. Get JWKS")
		fmt.Println("3. Verify JWT")
		fmt.Println("4. Exit")
		fmt.Print("\nSelect an option: ")

		choice, errReadingInput := reader.ReadString('\n')
		if errReadingInput != nil {
			fmt.Printf("Failed to read input: %v\n", errReadingInput)
			continue
		}
		choice = strings.TrimSpace(choice)

		switch choice {
		case "1":
			generateTokenInteractive(authService, reader)
		case "2":
			getJWKSInteractive(authService)
		case "3":
			verifyTokenInteractive(authService, reader)
		case "4":
			fmt.Println("Goodbye!")
			return
		default:
			fmt.Println("\n!!! Invalid token, please try again !!!\n")
		}
	}
}

func generateTokenInteractive(authService service.AuthService, reader *bufio.Reader) {
	fmt.Print("Enter device the user is logging in from: ")
	deviceType, errReadingDeviceTypeInput := reader.ReadString('\n')
	if errReadingDeviceTypeInput != nil {
		fmt.Printf("Failed to read input: %v\n", errReadingDeviceTypeInput)
		return
	}

	fmt.Print("Enter user ID: ")
	userId, errReadingUserIdInput := reader.ReadString('\n')
	if errReadingUserIdInput != nil {
		fmt.Printf("Failed to read input: %v\n", errReadingUserIdInput)
		return
	}
	userIdInInt, errParsingString := strconv.Atoi(strings.TrimSpace(userId))
	if errParsingString != nil {
		fmt.Printf("Invalid user ID: %v\n", errParsingString)
		return
	}

	fmt.Print("Enter username: ")
	username, errReadingUserUserNameInput := reader.ReadString('\n')
	if errReadingUserUserNameInput != nil {
		fmt.Printf("Failed to read input: %v\n", errReadingUserUserNameInput)
		return
	}

	username = strings.TrimSpace(username)

	user := &model.User{
		Id:       userIdInInt,
		Username: username,
	}

	token, err := authService.GenerateJwt(user, deviceType)
	if err != nil {
		fmt.Printf("Error generating token: %v\n", err)
		return
	}

	fmt.Printf("\nGenerated Token: %s\n", token)
}

func getJWKSInteractive(authService service.AuthService) {
	jwks, err := authService.GetPublicKeys()
	if err != nil {
		fmt.Printf("Error getting JWKS: %v\n", err)
		return
	}

	bytes, err := json.Marshal(jwks)
	if err != nil {
		fmt.Printf("Error getting marshalling data: %v\n", err)
		return
	}

	fmt.Printf("\nPublic JWKS: %+v\n", string(bytes))
}

func verifyTokenInteractive(authService service.AuthService, reader *bufio.Reader) {
	fmt.Print("Enter JWT token: ")
	token, _ := reader.ReadString('\n')
	token = strings.TrimSpace(token)

	claims, err := authService.VerifyToken(token)
	if err != nil {
		fmt.Printf("Error verifying token: %v\n", err)
		return
	}

	fmt.Printf("\nToken Claims: %+v\n", claims)
}

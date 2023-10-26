package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"net"
	"time"
	"encoding/json"
    	"io/ioutil"
)

type ToolConfig struct {
    Name      string `json:"name"`
    Repository string `json:"repository"`
    Command    string `json:"command"`
}

func main() {
    // Display the custom banner
    displayPinkBanner()

    // Read the tool configuration from "reconics.cfg"
    toolConfig, err := readToolConfig("reconics.cfg")
    if err != nil {
        fmt.Printf("Error reading tool configuration: %v\n", err)
        return
    }

    // Initialize the current directory
    currentDirectory, err := os.Getwd()
    if err != nil {
        fmt.Printf("Error getting the current directory: %v\n", err)
        return
    }

    // Clone and execute the tools based on the configuration
    for _, tool := range toolConfig {
        fmt.Printf("Cloning and executing %s...\n", tool.Name)
        if err := cloneAndExecuteTool(tool, currentDirectory); err != nil {
            fmt.Printf("Error cloning and executing %s: %v\n", tool.Name, err)
            continue
        }
    }

    // Continue with the main menu
    startMainMenu(currentDirectory)
}

func displayPinkBanner() {
	banner := `
mmmmm                              mmmmm    mmm   mmmm 
 #   "#  mmm    mmm    mmm   m mm     #    m"   " #"   "
 #mmmm" #"  #  #"  "  #" "#  #"  #    #    #      "#mmm 
 #   "m #""""  #      #   #  #   #    #    #          "#
 #    " "#mm"  "#mm"  "#m#"  #   #  mm#mm   "mmm" "mmm#"
`

	// Pink color (use ANSI escape codes for your specific terminal if supported)
	fmt.Print("\033[95m")
	fmt.Print(banner)
	fmt.Print("\033[0m")
}


func readToolConfig(filename string) ([]ToolConfig, error) {
    // Read the tool configuration from the JSON file.
    data, err := ioutil.ReadFile(filename)
    if err != nil {
        return nil, err
    }

    var config []ToolConfig  // Change this line to use a slice instead of a struct

    if err := json.Unmarshal(data, &config); err != nil {
        return nil, err
    }

    return config, nil
}


func cloneAndExecuteTool(tool ToolConfig, currentDirectory string) error {
    // Clone the tool repository
    cloneCmd := exec.Command("git", "clone", tool.Repository, tool.Name)
    cloneCmd.Stdout = os.Stdout
    cloneCmd.Stderr = os.Stderr
    if err := cloneCmd.Run(); err != nil {
        return err
    }

    // Change to the tool's directory
    if err := os.Chdir(tool.Name); err != nil {
        return err
    }

    // Execute the tool's command
    cmd := exec.Command("bash", "-c", tool.Command)
    cmd.Stdout = os.Stdout
    cmd.Stderr = os.Stderr
    return cmd.Run()
}

func startMainMenu(currentDirectory string) {
	 // Define your tools as needed
    tools := map[string]string{
        "testauth": "testauth",
        // Add more tools here as needed
    }

    for {
        fmt.Print("Available Tools:\n")
        for toolName := range tools {
            fmt.Printf("  - %s\n", toolName)
        }
        fmt.Print("Enter the tool name (or 'help' for help, 'exit' to exit): ")
        command := readUserInput()

        if command == "exit" {
            fmt.Println("Bye!")
            return
        }

        if command == "help" {
            displayHelp()
            continue
        }

        toolCommand, found := tools[command]
        if !found {
            fmt.Printf("Tool '%s' not found. Please select a valid tool or 'help' for options.\n", command)
            continue
        }

        // Change to the current directory
        os.Chdir(currentDirectory)

        // Execute the selected tool
        fmt.Printf("Executing '%s'...\n", command)

        if command == "testauth" {
            TestarUserandPass()
        } else {
            cmd := exec.Command("bash", "-c", toolCommand)
            cmd.Stdout = os.Stdout
            cmd.Stderr = os.Stderr

            if err := cmd.Run(); err != nil {
                fmt.Printf("Error executing tool '%s': %v\n", command, err)
            }
        }
    }
}

func readUserInput() string {
	var input string
	_, err := fmt.Scanln(&input)
	if err != nil {
		fmt.Println("Error reading input:", err)
	}
	return strings.TrimSpace(input)
}

func displayHelp() {
	fmt.Println("Available Commands:")
	fmt.Println("  - help: Displays the list of available commands.")
	fmt.Println("  - testauth: Test authentication with reference response.")
	fmt.Println("  - modbus: Run the Python script with an IP address argument in recon_modbus_functions directory.")
	fmt.Println("  - icssploit: Run the icssploit.py script in icssploit directory.")
	fmt.Println("  - exit: Exit ReconICS.")
}

func TestarUserandPass() {
	fmt.Println("Test authentication with reference response.")

	// Define a list of ICS and common Nmap ports to scan
	var portsToScan = []int{502, 20000, 4840, 102, 47808, 44818, 34962, 5094, 2404, 2405, 1883, 22, 80, 443, 8080, 445}

	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Enter the IP: ")
	ip, _ := reader.ReadString('\n')
	ip = strings.TrimSpace(ip)

	fmt.Print("Enter the user list path: ")
	userListPath, _ := reader.ReadString('\n')
	userListPath = strings.TrimSpace(userListPath)

	fmt.Print("Enter the password list path: ")
	passListPath, _ := reader.ReadString('\n')
	passListPath = strings.TrimSpace(passListPath)

	userFile, err := os.Open(userListPath)
	if err != nil {
		fmt.Printf("Error opening the user list file: %v\n", err)
		return
	}
	defer userFile.Close()

	passFile, err := os.Open(passListPath)
	if err != nil {
		fmt.Printf("Error opening the password list file: %v\n", err)
		return
	}
	defer passFile.Close()

	initialResp := TestarAuthentication(ip, portsToScan[0], "username", "password", false)
	if !initialResp {
		fmt.Println("Error getting reference response.")
		return
	}

	for _, port := range portsToScan {
		userScanner := bufio.NewScanner(userFile)
		for userScanner.Scan() {
			username := userScanner.Text()

			passScanner := bufio.NewScanner(passFile)
			for passScanner.Scan() {
				password := passScanner.Text()

				fmt.Printf("Testing %s:%d with user %s and password %s...\n", ip, port, username, password)

				// Test authentication based on referral response
				authSuccess := TestarAuthentication(ip, port, username, password, initialResp)
				if authSuccess {
					fmt.Printf("Access granted to %s:%d with user %s and password %s.\n", ip, port, username, password)
				}
			}
		}

		// Reset scanners to the beginning of files
		userFile.Seek(0, 0)
		passFile.Seek(0, 0)
	}
}

func TestarAuthentication(ip string, port int, username string, password string, initialResp bool) bool {
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", ip, port))
	if err != nil {
		fmt.Printf("Error connecting to server %s:%d: %v\n", ip, port, err)
		return false
	}
	defer conn.Close()

	// Wait for the server response
	time.Sleep(time.Second) // wait one second for the server response

	// Read the server answer after sending user and password
	resp, err := readResponse(conn)
	if err != nil {
		fmt.Printf("Error reading server response: %v\n", err)
		return false
	}

	// Check if the initial answer is different from the current answer
	return initialResp != (resp != "")
}

func readResponse(conn net.Conn) (string, error) {
	resp := make([]byte, 1024)
	n, err := conn.Read(resp)
	if err != nil {
		return "", err
	}
	return string(resp[:n]), nil
}



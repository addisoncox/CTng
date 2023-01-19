package miniclient

import (
	"fmt"
	"io"
	"net/http"
)

func Start() {
	Fetch("http://localhost:3000/sth", "STH")
	Fetch("http://localhost:3000/rev", "Revocation Information")
	Fetch("http://localhost:3000/pom", "Proof of Misbehavior")
	// Fetch("https://localhost:8002/", "Web Server")
}

func Fetch(url string, description string) {
	res, err := http.Get(url)
	if err != nil {
		fmt.Println("Error making http request:", err)
		return
	}

	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		fmt.Printf("Could not read %s response body: %s\n", description, err)
		return
	}

	if res.StatusCode != http.StatusOK {
		fmt.Printf("Failed to get %s: %s\n", description, resBody)
	} else {
		fmt.Printf("%s: %s\n", description, resBody)
	}
	fmt.Println();
}

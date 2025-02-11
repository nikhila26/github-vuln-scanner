package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// Vulnerability struct to store vulnerability data
type Vulnerability struct {
	ID             string    `json:"id" gorm:"primaryKey"`
	Severity       string    `json:"severity"`
	CVSS           float64   `json:"cvss"`
	Status         string    `json:"status"`
	PackageName    string    `json:"package_name"`
	CurrentVersion string    `json:"current_version"`
	FixedVersion   string    `json:"fixed_version"`
	Description    string    `json:"description"`
	PublishedDate  string    `json:"published_date"`
	Link           string    `json:"link"`
	SourceFile     string    `json:"source_file"`
	ScanTime       time.Time `json:"scan_time"`
}

var db *gorm.DB

// Initialize the database connection
func init() {
	var err error
	db, err = gorm.Open(sqlite.Open("vulnerabilities.db"), &gorm.Config{})
	if err != nil {
		log.Fatalf("[ERROR] Failed to connect to database: %v", err)
	}

	if err := db.AutoMigrate(&Vulnerability{}); err != nil {
		log.Fatalf("[ERROR] Failed to migrate database schema: %v", err)
	}

	log.Println("[INFO] Database connected and migrated successfully!")
}

// ScanRepo fetches JSON files from GitHub and stores their content
func ScanRepo(c *gin.Context) {
	var req struct {
		Repo  string   `json:"repo"`
		Files []string `json:"files"`
	}

	if err := c.BindJSON(&req); err != nil {
		log.Println("[ERROR] Invalid JSON request received for /scan")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	log.Printf("[INFO] Scanning repo: %s for files: %v", req.Repo, req.Files)

	var wg sync.WaitGroup
	sem := make(chan struct{}, 3) // Limit concurrency to 3 goroutines

	for _, file := range req.Files {
		wg.Add(1)
		sem <- struct{}{}
		go func(file string) {
			defer wg.Done()
			fetchAndStoreFile(req.Repo, file)
			<-sem
		}(file)
	}

	wg.Wait()
	log.Println("[INFO] Scanning completed successfully!")
	c.JSON(http.StatusOK, gin.H{"message": "Scanning completed successfully"})
}

// Fetch and store JSON file from GitHub
// Fetch and store JSON file from GitHub (with 2 retry attempts)
func fetchAndStoreFile(repo, file string) {
	url := fmt.Sprintf("https://raw.githubusercontent.com/%s/main/%s", repo, file)
	log.Printf("[INFO] Fetching file: %s from repository: %s", file, repo)

	var body []byte
	var lastErr error // Store last error for logging

	// Retry logic with 2 attempts
	for attempt := 1; attempt <= 2; attempt++ {
		resp, err := http.Get(url)
		if err != nil {
			lastErr = err
		} else {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				body, err = ioutil.ReadAll(resp.Body)
				if err == nil && len(body) > 0 {
					break
				}
				lastErr = err
			} else {
				lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
			}
		}

		if attempt < 2 {
			backoff := time.Duration(2<<attempt) * time.Second // 2s, 4s
			log.Printf("[WARNING] Attempt %d: Failed to fetch file: %s (Error: %v). Retrying in %v...", attempt, file, lastErr, backoff)
			time.Sleep(backoff)
		} else {
			log.Printf("[ERROR] Failed to fetch file: %s after 2 attempts. Last error: %v", file, lastErr)
			return
		}
	}

	// Validate the content
	if len(body) == 0 {
		log.Printf("[ERROR] Skipping file %s: Empty or missing content after 2 attempts.", file)
		return
	}

	// Parse JSON and extract vulnerabilities
	var scanData []map[string]interface{}
	if err := json.Unmarshal(body, &scanData); err != nil {
		log.Printf("[ERROR] Error parsing JSON in file: %s (Error: %v)", file, err)
		return
	}

	scanTime := time.Now()
	var validVulnerabilities []Vulnerability

	for _, entry := range scanData {
		if scanResults, exists := entry["scanResults"].(map[string]interface{}); exists {
			if vulnerabilities, found := scanResults["vulnerabilities"].([]interface{}); found {
				for _, v := range vulnerabilities {
					var vuln Vulnerability
					vulnMap := v.(map[string]interface{})

					vuln.ID = getString(vulnMap, "id")
					vuln.Severity = getString(vulnMap, "severity")
					vuln.CVSS = getFloat(vulnMap, "cvss")
					vuln.Status = getString(vulnMap, "status")
					vuln.PackageName = getString(vulnMap, "package_name")
					vuln.CurrentVersion = getString(vulnMap, "current_version")
					vuln.FixedVersion = getString(vulnMap, "fixed_version")
					vuln.Description = getString(vulnMap, "description")
					vuln.PublishedDate = getString(vulnMap, "published_date")
					vuln.Link = getString(vulnMap, "link")
					vuln.SourceFile = file
					vuln.ScanTime = scanTime

					validVulnerabilities = append(validVulnerabilities, vuln)
				}
			}
		}
	}

	if len(validVulnerabilities) > 0 {
		for _, v := range validVulnerabilities {
			db.Save(&v)
		}
		log.Printf("[INFO] Inserted/Updated %d records from file: %s", len(validVulnerabilities), file)
	} else {
		log.Printf("[WARNING] No valid records found in file: %s", file)
	}
}

// QueryVulnerabilities filters vulnerabilities by severity
func QueryVulnerabilities(c *gin.Context) {
	var req struct {
		Filters struct {
			Severity string `json:"severity"`
		} `json:"filters"`
	}

	if err := c.BindJSON(&req); err != nil {
		log.Println("[ERROR] Invalid JSON request received for /query")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	log.Printf("[INFO] Querying database for vulnerabilities with severity: %s", req.Filters.Severity)

	var results []Vulnerability
	db.Where("severity = ?", req.Filters.Severity).Find(&results)

	log.Printf("[INFO] Found %d vulnerabilities matching severity: %s", len(results), req.Filters.Severity)
	c.JSON(http.StatusOK, results)
}

func main() {
	r := gin.Default()
	r.POST("/scan", ScanRepo)
	r.POST("/query", QueryVulnerabilities)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("[INFO] Starting server on port %s...", port)
	r.Run(":" + port)
}

// Helper functions for JSON parsing
func getString(m map[string]interface{}, key string) string {
	if val, ok := m[key].(string); ok {
		return val
	}
	return ""
}

func getFloat(m map[string]interface{}, key string) float64 {
	if val, ok := m[key].(float64); ok {
		return val
	}
	return 0.0
}

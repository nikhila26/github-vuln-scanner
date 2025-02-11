package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

// Setup the test router
func setupRouter() *gin.Engine {
	r := gin.Default()
	r.POST("/scan", ScanRepo)
	r.POST("/query", QueryVulnerabilities)
	return r
}

// Test Scan API
func TestScanRepo(t *testing.T) {
	r := setupRouter()

	// Mock request payload
	requestBody, _ := json.Marshal(map[string]interface{}{
		"repo": "velancio/vulnerability_scans",
		"files": []string{
			"vulnscan1011.json",
		},
	})

	req, _ := http.NewRequest("POST", "/scan", bytes.NewBuffer(requestBody))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "Scanning completed successfully")
}

// Test Query API
func TestQueryVulnerabilities(t *testing.T) {
	r := setupRouter()

	// Mock request payload
	requestBody, _ := json.Marshal(map[string]interface{}{
		"filters": map[string]string{
			"severity": "HIGH",
		},
	})

	req, _ := http.NewRequest("POST", "/query", bytes.NewBuffer(requestBody))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

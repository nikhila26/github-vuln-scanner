GitHub Vulnerability Scanner
Introduction:
This is a Go-based REST API service that:
    •	Scans JSON files from a GitHub repository and stores them in an SQLite database.
    •	Queries stored vulnerabilities based on the given severity filter.
Features:
    •	Fetches multiple JSON files from a GitHub repository.
    •	Stores vulnerabilities in a local SQLite database.
    •	Exposes two REST APIs: POST /scan and POST /query.
    •	Supports both manual execution and Docker-based execution.
Prerequisites
Ensure you have the following installed:
    1.	Go 1.20 or later
    2.	Postman or cURL for testing API endpoints (I used Postman).
    3.	SQLite (automatically created during execution)
    4.	Docker (for containerized execution)
Running the Application Manually (Without Docker)
1. Navigate to Your Folder
    •	I already created the folder, move into it:
    •	cd C:\Users\nikhi\OneDrive\Desktop\github-vuln-scanner
2. Initialize Go Modules (If Not Done Already)
    •	go mod init github-vuln-scanner
3. Install Dependencies
    •	go mod tidy
4. Run the Application
    •	go run main.go
    •	The server will start at http://localhost:8080.

Testing the API Endpoints Manually
Scanning the GitHub Repository
    •	Endpoint: POST /scan
    •	Purpose: Fetches multiple JSON files from a GitHub repository and stores them in the database.
Request:
{
  "repo": "velancio/vulnerability_scans",
  "files": [
    "vulnscan1011.json",
    "vulnscan1213.json",
    "vulnscan15.json",
    "vulnscan16.json",
    "vulnscan18.json",
    "vulnscan19.json",
    "vulnscan456.json",
    "vulnscan789.json",
    "vulscan123.json"
  ]
}
Expected Response:
{
  "message": "Scanning completed successfully"
}
Postman Steps:
    1.	Open Postman.
    2.	Select POST request.
    3.	Enter URL: http://localhost:8080/scan
    4.	Go to Body → raw → Select JSON format.
    5.	Paste the request body and click Send.
Querying Vulnerabilities by Severity
    •	Endpoint: POST /query
    •	Purpose: Retrieves vulnerability records that match a HIGH severity filter.
Request:
{
  "filters": {
    "severity": "HIGH"
  }
}
Expected Response Example:
[
  {
    "id": "CVE-2024-1234",
    "severity": "HIGH",
    "cvss": 8.5,
    "status": "fixed",
    "package_name": "openssl",
    "current_version": "1.1.1t-r0",
    "fixed_version": "1.1.1u-r0",
    "description": "Buffer overflow vulnerability in OpenSSL",
    "published_date": "2024-01-15T00:00:00Z",
    "link": "https://nvd.nist.gov/vuln/detail/CVE-2024-1234"
  }
]
Postman Steps:
    1.	Open Postman.
    2.	Select POST request.
    3.	Enter URL: http://localhost:8080/query
    4.	Go to Body → raw → Select JSON format.
    5.	Paste the request body and click Send.
5. Troubleshooting
    •	Error: Connection refused
        o	Ensure your Go server is running using go run main.go.
    •	Error: No results in /query
        o	Make sure you scanned JSON files first using the /scan API.
Running the Application with Docker
1. Build the Docker Image
    •	docker build -t vulnscanner .
2. Run the Docker Container
    •	docker run -p 8080:8080 vulnscanner
    •	The application will be running inside a Docker container.
3. Check Running Containers
    •	docker ps
4. Stop the Container
    •	docker stop <container_id>
Troubleshooting
Docker Issues
If you encounter:
    •	ERROR [internal] load metadata for docker.io/library/golang:1.20
    •	Run:
        o	docker login
    •	If go mod tidy fails inside the container:
        o	docker build --no-cache -t vulnscanner .
Database Issues
    •	If SQLite does not create a file, check:
        o	ls vulnerabilities.db
    •	If needed, manually create a new database file:
        o	touch vulnerabilities.db

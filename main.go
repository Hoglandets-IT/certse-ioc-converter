package main

import (
	"encoding/csv"
	"fmt"
	"os"
	"strings"
	"time"
)

// Predefined array for output headers
var outputHeaders []string = []string{
	"IndicatorType",
	"IndicatorValue",
	"ExpirationTime",
	"Action",
	"Severity",
	"Title",
	"Description",
	"RecommendedActions",
	"RbacGroups",
	"Category",
	"MitreTechniques",
	"GenerateAlert",
}

// Map source columns to target
var indicatorMap map[string]string = map[string]string{
	"ip-src": "IpAddress",
	"ip-dst": "IpAddress",
	"sha256": "FileSha256",
	"sha1":   "FileSha1",
	"url":    "Url",
	"domain": "DomainName",
}

// Ensure a string value is not empty
func ensureValue(value string, def string) string {
	if value != "" {
		return value
	}
	return def
}

// Translate indicator type via indicatorMap
func translateIndicator(indicator string) string {
	if val, ok := indicatorMap[indicator]; ok {
		return val
	}
	return ""
}

// Create a map from a row in the source file
func createMapFromRow(row []string, headers []string) map[string]string {
	rowMap := map[string]string{}
	for j, header := range headers {
		rowMap[header] = row[j]
	}
	return rowMap
}

// Get action from type
func getActionType(indicatorType string) string {
	if indicatorType == "sha1" || indicatorType == "sha256" {
		return "BlockAndRemediate"
	}
	return "Block"
}

func main() {
	// Get filename from first argument
	filename := os.Args[1]

	// Read CSV file
	inputfile, err := os.Open(filename)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer inputfile.Close()

	// Parse CSV
	reader := csv.NewReader(inputfile)
	records, err := reader.ReadAll()
	if err != nil {
		fmt.Println(err)
		return
	}

	// Create result container
	result := [][]string{}

	// Add output headers to result
	result = append(result, outputHeaders)

	// Extract the input headers for mapping
	inputHeaders := records[0]

	for _, record := range records[1:] {
		// Create field map from row
		tmpMap := createMapFromRow(record, inputHeaders)

		// Skip if no equivalent type exists in destination format
		if ensureValue(translateIndicator(tmpMap["type"]), "INVALID") == "INVALID" {
			continue
		}

		// Add row to result
		result = append(result, []string{
			// IndicatorType (Mapped via indicatorMap)
			ensureValue(translateIndicator(tmpMap["type"]), "INVALID"),

			// IndicatorValue (1:1, but replace [.] with . for IP addresses)
			strings.Replace(ensureValue(tmpMap["value"], "INVALID"), "[.]", ".", -1),

			// Generate ExpirationTime Y-m-dTH:i:s.0Z 10 days in the future
			time.Now().Add(10 * 24 * time.Hour).Format("2006-01-02T15:04:05.0Z"),

			// Action to take
			getActionType(tmpMap["type"]),

			// Severity
			"High",

			// Title (from object_name in source file, defaults to IOC)
			ensureValue(tmpMap["object_name"], "IOC") + " FROM CERT-SE " + time.Now().Format("2006-01-02"),

			// Description (from source comment)
			ensureValue(tmpMap["comment"], "No description"),

			// RecommendedActions
			"Remediate",

			// RbacGroups
			"",

			// Category
			"",

			// MitreTechniques
			"",

			// GenerateAlert
			"TRUE",
		})
	}

	// Open output file
	outputfile, err := os.Create(strings.Replace(filename, ".csv", "-ioc.csv", -1))
	if err != nil {
		fmt.Println(err)
		return
	}
	defer outputfile.Close()

	// Write result to output file
	writer := csv.NewWriter(outputfile)
	writer.WriteAll(result)
	writer.Flush()
}

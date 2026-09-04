// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoggingContractValuesAreUniqueAndSnakeCase(t *testing.T) {
	snakeCase := regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

	tests := []struct {
		name   string
		values []string
	}{
		{name: "fields", values: logFieldsAsStrings(loggingContractFields())},
		{name: "events", values: logEventsAsStrings(loggingContractEvents())},
		{name: "handlers", values: logHandlersAsStrings(loggingContractHandlers())},
		{name: "failure categories", values: logFailureCategoriesAsStrings(loggingContractFailureCategories())},
		{name: "forbidden fields", values: logFieldsAsStrings(forbiddenLogFields())},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			seen := map[string]struct{}{}
			for _, value := range test.values {
				require.NotEmpty(t, value)
				assert.True(t, snakeCase.MatchString(value), "%q must be snake_case", value)
				_, exists := seen[value]
				assert.False(t, exists, "%q is duplicated", value)
				seen[value] = struct{}{}
			}
		})
	}
}

func TestLoggingContractFieldsExcludeForbiddenFields(t *testing.T) {
	allowed := map[string]struct{}{}
	for _, field := range loggingContractFields() {
		allowed[string(field)] = struct{}{}
	}

	for _, field := range forbiddenLogFields() {
		_, exists := allowed[string(field)]
		assert.False(t, exists, "forbidden field %q must not be an allowed contract field", field)
	}
}

func TestLoggingContractContainsIssue51RequiredNames(t *testing.T) {
	assert.Contains(t, logFieldsAsStrings(loggingContractFields()), "component")
	assert.Contains(t, logFieldsAsStrings(loggingContractFields()), "failure_category")
	assert.Contains(t, logEventsAsStrings(loggingContractEvents()), "token_exchange_failed")
	assert.Contains(t, logFailureCategoriesAsStrings(loggingContractFailureCategories()), "provider_metadata")
	assert.Contains(t, logFailureCategoriesAsStrings(loggingContractFailureCategories()), "generated_claim_validation")
	assert.Contains(t, logHandlersAsStrings(loggingContractHandlers()), "oauth_exchange")
}

func TestLoggingContractDocumentReferencesConstants(t *testing.T) {
	docPath := filepath.Join("..", "..", "docs", "logging-contract.md")
	data, err := os.ReadFile(docPath)
	require.NoError(t, err)
	doc := string(data)

	for _, field := range loggingContractFields() {
		assert.Contains(t, doc, "`"+string(field)+"`")
	}
	for _, event := range loggingContractEvents() {
		assert.Contains(t, doc, "`"+string(event)+"`")
	}
	for _, category := range loggingContractFailureCategories() {
		assert.Contains(t, doc, "`"+string(category)+"`")
	}
	for _, field := range forbiddenLogFields() {
		assert.Contains(t, doc, "`"+string(field)+"`")
	}
}

func TestForbiddenLogFieldsCoverSecretTerms(t *testing.T) {
	joined := strings.Join(logFieldsAsStrings(forbiddenLogFields()), " ")
	for _, term := range []string{"jwt", "access_token", "bootstrap_token", "refresh_token", "secret", "authorization"} {
		assert.Contains(t, joined, term)
	}
}

func logFieldsAsStrings(fields []LogField) []string {
	out := make([]string, 0, len(fields))
	for _, field := range fields {
		out = append(out, string(field))
	}
	return out
}

func logEventsAsStrings(events []LogEvent) []string {
	out := make([]string, 0, len(events))
	for _, event := range events {
		out = append(out, string(event))
	}
	return out
}

func logHandlersAsStrings(handlers []LogHandler) []string {
	out := make([]string, 0, len(handlers))
	for _, handler := range handlers {
		out = append(out, string(handler))
	}
	return out
}

func logFailureCategoriesAsStrings(categories []LogFailureCategory) []string {
	out := make([]string, 0, len(categories))
	for _, category := range categories {
		out = append(out, string(category))
	}
	return out
}

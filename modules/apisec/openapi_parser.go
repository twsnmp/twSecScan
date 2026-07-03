package apisec

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
)

// APIEndpoint represents a single API route extracted from OpenAPI spec
type APIEndpoint struct {
	Path        string               `json:"path"`
	Method      string               `json:"method"`
	QueryParams []APIParameter       `json:"queryParams"`
	PathParams  []APIParameter       `json:"pathParams"`
	RequestBody *APIRequestBodySchema `json:"requestBody,omitempty"`
}

// APIParameter represents a parameter of the API endpoint
type APIParameter struct {
	Name     string `json:"name"`
	Required bool   `json:"required"`
	Type     string `json:"type"` // "string", "integer", "boolean", etc.
}

// APIRequestBodySchema represents request body JSON schema
type APIRequestBodySchema struct {
	Type       string                  `json:"type"` // e.g. "object"
	Properties map[string]APIParameter `json:"properties"`
	Required   []string                `json:"required"`
}

// LoadOpenAPISpec loads and validates an OpenAPI 3.0 specification from a file path or URL
func LoadOpenAPISpec(ctx context.Context, pathOrURL string) (*openapi3.T, error) {
	var data []byte
	var err error

	if strings.HasPrefix(pathOrURL, "http://") || strings.HasPrefix(pathOrURL, "https://") {
		// Verify URL format
		_, err = url.ParseRequestURI(pathOrURL)
		if err != nil {
			return nil, fmt.Errorf("invalid URL format: %w", err)
		}

		req, err := http.NewRequestWithContext(ctx, "GET", pathOrURL, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch URL: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("failed to fetch URL, HTTP status: %d", resp.StatusCode)
		}

		data, err = io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read response body: %w", err)
		}
	} else {
		// Read local file
		data, err = os.ReadFile(pathOrURL)
		if err != nil {
			return nil, fmt.Errorf("failed to read file: %w", err)
		}
	}

	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromData(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse OpenAPI spec: %w", err)
	}

	// Validate the document
	err = doc.Validate(ctx)
	if err != nil {
		return nil, fmt.Errorf("invalid OpenAPI specification: %w", err)
	}

	return doc, nil
}

// ExtractEndpoints processes the loaded OpenAPI spec and returns list of APIEndpoints
func ExtractEndpoints(doc *openapi3.T) []APIEndpoint {
	var endpoints []APIEndpoint

	if doc == nil || doc.Paths == nil {
		return endpoints
	}

	for pathStr, pathItem := range doc.Paths.Map() {
		if pathItem == nil {
			continue
		}

		for method, operation := range pathItem.Operations() {
			if operation == nil {
				continue
			}

			endpoint := APIEndpoint{
				Path:   pathStr,
				Method: strings.ToUpper(method),
			}

			// Extract parameters (merging path-level parameters and operation parameters)
			var allParams []*openapi3.ParameterRef
			if pathItem.Parameters != nil {
				allParams = append(allParams, pathItem.Parameters...)
			}
			if operation.Parameters != nil {
				allParams = append(allParams, operation.Parameters...)
			}

			for _, paramRef := range allParams {
				if paramRef == nil || paramRef.Value == nil {
					continue
				}
				param := paramRef.Value
				
				paramType := "string"
				if param.Schema != nil && param.Schema.Value != nil && param.Schema.Value.Type != nil {
					if len(*param.Schema.Value.Type) > 0 {
						paramType = (*param.Schema.Value.Type)[0]
					}
				}

				apiParam := APIParameter{
					Name:     param.Name,
					Required: param.Required,
					Type:     paramType,
				}

				switch param.In {
				case openapi3.ParameterInQuery:
					endpoint.QueryParams = append(endpoint.QueryParams, apiParam)
				case openapi3.ParameterInPath:
					endpoint.PathParams = append(endpoint.PathParams, apiParam)
				}
			}

			// Extract Request Body for JSON schemas
			if operation.RequestBody != nil && operation.RequestBody.Value != nil {
				content := operation.RequestBody.Value.Content
				if jsonContent, exists := content["application/json"]; exists && jsonContent != nil && jsonContent.Schema != nil {
					schema := jsonContent.Schema.Value
					if schema != nil {
						schemaType := "object"
						if schema.Type != nil && len(*schema.Type) > 0 {
							schemaType = (*schema.Type)[0]
						}
						reqBody := &APIRequestBodySchema{
							Type:       schemaType,
							Properties: make(map[string]APIParameter),
							Required:   schema.Required,
						}

						for propName, propRef := range schema.Properties {
							if propRef == nil || propRef.Value == nil {
								continue
							}
							prop := propRef.Value
							
							propType := "string"
							if prop.Type != nil && len(*prop.Type) > 0 {
								propType = (*prop.Type)[0]
							}
							
							reqBody.Properties[propName] = APIParameter{
								Name: propName,
								Type: propType,
							}
						}
						endpoint.RequestBody = reqBody
					}
				}
			}

			endpoints = append(endpoints, endpoint)
		}
	}

	return endpoints
}

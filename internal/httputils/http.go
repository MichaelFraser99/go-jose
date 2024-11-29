package httputils

import (
	"fmt"
	"github.com/MichaelFraser99/go-jose/joseerror"
	"net/http"
)

func RetrieveResource(client *http.Client, url, alias string) (*http.Response, error) {
	if client == nil {
		return nil, fmt.Errorf("%w%s is specified but no client exists", joseerror.ApplicationError, alias)
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("%wfailed to create request to specified %s: %w", joseerror.ApplicationError, alias, err)
	}

	response, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%wfailed to retrieve %s: %w", joseerror.ApplicationError, alias, err)
	}

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%wfailed to retrieve %s: received status code %d", joseerror.ApplicationError, alias, response.StatusCode)
	}

	return response, nil
}

package caddy2_radius_auth

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

// checkRadiusConcurrent sends concurrent requests to multiple RADIUS servers
// Returns true, nil if any server returns Access-Accept
// Returns false, nil if no Access-Accept but any server returns Reject
// Returns false, error for other cases (errors or unknown response codes)
func (r HTTPRadiusAuth) checkRadiusConcurrent(username, password string) (bool, error) {
	if len(r.Servers) == 0 {
		return false, errors.New("no RADIUS servers configured")
	}

	packet := radius.New(radius.CodeAccessRequest, []byte(r.Secret))
	err := rfc2865.UserName_SetString(packet, username)
	if err != nil {
		return false, fmt.Errorf("rfc2865: setting username string error: %w", err)
	}
	err = rfc2865.UserPassword_SetString(packet, password)
	if err != nil {
		return false, fmt.Errorf("rfc2865: setting password string error: %w", err)
	}

	timeout, _ := time.ParseDuration(r.Timeout)

	type result struct {
		code   radius.Code
		err    error
		server string
	}

	ch := make(chan result, len(r.Servers))
	var wg sync.WaitGroup

	for _, server := range r.Servers {
		wg.Add(1)
		go func(srv string) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.TODO(), timeout)
			defer cancel()
			resp, err := radius.Exchange(ctx, packet, srv)
			if err != nil {
				ch <- result{code: 0, err: err, server: srv}
				return
			}
			ch <- result{code: resp.Code, err: nil, server: srv}
		}(server)
	}

	go func() {
		wg.Wait()
		close(ch)
	}()

	hasAccessAccept := false
	hasReject := false
	serverResults := make(map[string]struct {
		code radius.Code
		err  error
	})

	for res := range ch {
		serverResults[res.server] = struct {
			code radius.Code
			err  error
		}{code: res.code, err: res.err}

		if res.code == radius.CodeAccessAccept {
			hasAccessAccept = true
		} else if res.code == radius.CodeAccessReject {
			hasReject = true
		}
	}

	// Case 1: Any server returns Access-Accept
	if hasAccessAccept {
		return true, nil
	}

	// Case 2: No Access-Accept but any server returns Reject
	if hasReject {
		return false, nil
	}

	// Case 3: Other cases - wrap errors or unknown codes
	errorMsg := "RADIUS authentication issues: "
	for server, result := range serverResults {
		if result.err != nil {
			errorMsg += fmt.Sprintf("%s error: %v; ", server, result.err)
		} else if result.code != 0 {
			errorMsg += fmt.Sprintf("%s returned unknown code: %v; ", server, result.code)
		} else {
			errorMsg += fmt.Sprintf("%s: no response; ", server)
		}
	}

	return false, fmt.Errorf(errorMsg)
}

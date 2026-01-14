package main

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/go-harden/interactsh-lite/oobclient"
)

const timestampFormat = "2006-01-02 15:04:05"

func formatStandard(w io.Writer, i *oobclient.Interaction, verbose bool) error {
	protocol := strings.ToUpper(i.Protocol)
	timestamp := i.Timestamp.Format(timestampFormat)
	var line string
	switch strings.ToLower(i.Protocol) {
	case "dns":
		line = fmt.Sprintf("[%s] Received %s interaction (%s) from %s at %s",
			i.FullId, protocol, i.QType, i.RemoteAddress, timestamp)
	case "smb", "responder":
		line = fmt.Sprintf("[%s] Received %s interaction at %s",
			i.FullId, protocol, timestamp)
	default:
		line = fmt.Sprintf("[%s] Received %s interaction from %s at %s",
			i.FullId, protocol, i.RemoteAddress, timestamp)
	}

	if _, err := fmt.Fprintln(w, line); err != nil {
		return err
	}

	if verbose {
		if i.RawRequest != "" {
			_, _ = fmt.Fprintf(w, "-----------\n%s Request\n-----------\n\n%s\n", protocol, i.RawRequest)
		}
		if i.RawResponse != "" {
			_, _ = fmt.Fprintf(w, "------------\n%s Response\n------------\n\n%s\n", protocol, i.RawResponse)
		}
	}
	return nil
}

type jsonInteraction struct {
	Protocol      string    `json:"protocol"`
	UniqueID      string    `json:"unique-id"`
	FullId        string    `json:"full-id"`
	QType         string    `json:"q-type,omitempty"`
	RawRequest    string    `json:"raw-request,omitempty"`
	RawResponse   string    `json:"raw-response,omitempty"`
	SMTPFrom      string    `json:"smtp-from,omitempty"`
	RemoteAddress string    `json:"remote-address"`
	Timestamp     time.Time `json:"timestamp"`
}

func formatJSON(w io.Writer, i *oobclient.Interaction) error {
	ji := jsonInteraction{
		Protocol:      strings.ToLower(i.Protocol),
		UniqueID:      i.UniqueID,
		FullId:        i.FullId,
		QType:         i.QType,
		RawRequest:    i.RawRequest,
		RawResponse:   i.RawResponse,
		SMTPFrom:      i.SMTPFrom,
		RemoteAddress: i.RemoteAddress,
		Timestamp:     i.Timestamp.UTC(),
	}

	data, err := json.Marshal(ji)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(w, string(data))
	return err
}

func compilePatterns(patterns []string, kind string) ([]*regexp.Regexp, error) {
	regexes := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("invalid %s pattern %q: %w", kind, p, err)
		}
		regexes = append(regexes, re)
	}
	return regexes, nil
}

// shouldDisplay checks protocol filters (OR behavior) and regex patterns.
func shouldDisplay(i *oobclient.Interaction, dnsOnly, httpOnly, smtpOnly bool, matchRegexes, filterRegexes []*regexp.Regexp) bool {
	noFilter := !dnsOnly && !httpOnly && !smtpOnly

	// Protocol filters use OR logic: show if no filter set, or if matching filter is set
	switch strings.ToLower(i.Protocol) {
	case "dns":
		if !noFilter && !dnsOnly {
			return false
		}
	case "http":
		if !noFilter && !httpOnly {
			return false
		}
	case "smtp":
		if !noFilter && !smtpOnly {
			return false
		}
	default:
		// FTP, LDAP, SMB only show when no protocol filter is active
		if !noFilter {
			return false
		}
	}

	matchesInteraction := func(re *regexp.Regexp, i *oobclient.Interaction) bool {
		return re.MatchString(i.FullId) || re.MatchString(i.RawRequest) ||
			re.MatchString(i.RawResponse) || re.MatchString(i.RemoteAddress)
	}

	// Match patterns: at least one must match if specified
	if len(matchRegexes) > 0 {
		var matched bool
		for _, re := range matchRegexes {
			if matchesInteraction(re, i) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Filter patterns: none must match
	for _, re := range filterRegexes {
		if matchesInteraction(re, i) {
			return false
		}
	}

	return true
}

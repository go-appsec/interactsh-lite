package oobsrv

import (
	"slices"
	"strings"

	"github.com/go-appsec/interactsh-lite/oobclient"
)

// cidAlphabetTable is a precomputed lookup table for the CID base32 alphabet.
var cidAlphabetTable [256]bool

// alphanumericTable is a precomputed lookup table for lowercase alphanumeric (a-z, 0-9).
var alphanumericTable [256]bool

func init() {
	for i := range oobclient.CIDEncodingAlphabet {
		cidAlphabetTable[oobclient.CIDEncodingAlphabet[i]] = true
	}
	for c := byte('a'); c <= 'z'; c++ {
		alphanumericTable[c] = true
	}
	for c := byte('0'); c <= '9'; c++ {
		alphanumericTable[c] = true
	}
}

// minNonceLength is the minimum nonce suffix after the correlation ID for combined matching.
const minNonceLength = 3

// Match holds the result of a correlation ID match.
type Match struct {
	UniqueID string // matched correlation ID (first cidLength chars)
	FullID   string // everything before domain suffix, no trailing dot
}

// scanLabels applies two-tier sliding window matching to dot-separated labels.
// Tier 1 slides a window of cidLength+minNonceLength across each label.
// Tier 2 checks labels of exact cidLength (nonce split from cid).
// onMatch receives (candidate, label) for each hit. Return false to stop.
func scanLabels(input string, cidLength int, lookup func(string) bool, onMatch func(candidate, label string) bool) {
	windowSize := cidLength + minNonceLength

	for remaining := input; remaining != ""; {
		var label string
		label, remaining, _ = strings.Cut(remaining, ".")
		if len(label) < windowSize {
			continue
		}

		for pos := 0; pos <= len(label)-windowSize; pos++ {
			window := label[pos : pos+windowSize]
			candidate := window[:cidLength]
			if !isCIDBase32(candidate) || !isAlphanumeric(window[cidLength:]) {
				continue
			}
			if lookup(candidate) {
				if !onMatch(candidate, label) {
					return
				}
			}
		}
	}

	// bare ID fallback
	for remaining := input; remaining != ""; {
		var label string
		label, remaining, _ = strings.Cut(remaining, ".")
		if len(label) != cidLength || !isCIDBase32(label) {
			continue
		}
		if lookup(label) {
			if !onMatch(label, label) {
				return
			}
		}
	}
}

// MatchCorrelationID scans input for registered correlation IDs using two-tier
// sliding window. lookup checks if a candidate is registered.
func MatchCorrelationID(input string, cidLength int, domains []string, lookup func(string) bool) []Match {
	input = strings.ToLower(input)
	var matches []Match

	scanLabels(input, cidLength, lookup, func(candidate, _ string) bool {
		if matchesContain(matches, candidate) {
			return true
		}
		matches = append(matches, Match{UniqueID: candidate})
		return true
	})

	fullID := extractFullID(input, domains)
	for i := range matches {
		matches[i].FullID = fullID
	}

	return matches
}

// MatchCorrelationIDEverywhere splits input by delimiters and runs a single-pass
// sliding window. FullID is the matched window text.
func MatchCorrelationIDEverywhere(input string, cidLength int, lookup func(string) bool) []Match {
	var scanEverywhereDelimiters = [256]bool{
		'.':  true,
		'\n': true,
		'\t': true,
		'"':  true,
		'\'': true,
	}
	chunks := strings.FieldsFunc(strings.ToLower(input), func(r rune) bool {
		if r < 256 {
			return scanEverywhereDelimiters[byte(r)]
		}
		return false
	})

	windowSize := cidLength + minNonceLength
	var matches []Match
	seen := make(map[string]bool)
	for _, chunk := range chunks {
		if len(chunk) < windowSize {
			continue
		}

		for pos := 0; pos <= len(chunk)-windowSize; pos++ {
			window := chunk[pos : pos+windowSize]
			candidate := window[:cidLength]
			if !isCIDBase32(candidate) || !isAlphanumeric(window[cidLength:]) {
				continue
			}
			if !seen[candidate] && lookup(candidate) {
				seen[candidate] = true
				matches = append(matches, Match{
					UniqueID: candidate,
					FullID:   window,
				})
			}
		}
	}

	return matches
}

// matchesContain checks if any match has the given UniqueID.
func matchesContain(matches []Match, id string) bool {
	return slices.ContainsFunc(matches, func(m Match) bool { return m.UniqueID == id })
}

// extractFullID strips the domain suffix from input. Domains must be pre-sorted longest-first.
func extractFullID(input string, domains []string) string {
	for _, domain := range domains {
		if result, ok := strings.CutSuffix(input, "."+domain); ok {
			return result
		}
	}
	return input
}

// MatchLDAPCorrelationID scans an LDAP BaseDN for registered correlation IDs.
// Splits on = and , then applies two-tier sliding window per part.
func MatchLDAPCorrelationID(baseDN string, cidLength int, domains []string, lookup func(string) bool) []Match {
	parts := strings.FieldsFunc(baseDN, func(r rune) bool {
		return r == '=' || r == ','
	})

	var matches []Match
	for _, part := range parts {
		part = strings.ToLower(strings.TrimSpace(part))
		if part == "" {
			continue
		}

		var partMatches []Match
		scanLabels(part, cidLength,
			func(candidate string) bool {
				return !matchesContain(matches, candidate) && !matchesContain(partMatches, candidate) && lookup(candidate)
			},
			func(candidate, _ string) bool {
				partMatches = append(partMatches, Match{UniqueID: candidate})
				return true
			})

		fullID := extractFullID(part, domains)
		for i := range partMatches {
			partMatches[i].FullID = fullID
		}
		matches = append(matches, partMatches...)
	}

	return matches
}

// isCIDBase32 checks that all bytes in s belong to the CID base32 alphabet.
func isCIDBase32(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i := range len(s) {
		if !cidAlphabetTable[s[i]] {
			return false
		}
	}
	return true
}

// isAlphanumeric checks that all bytes in s are lowercase alphanumeric (a-z, 0-9).
func isAlphanumeric(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i := range len(s) {
		if !alphanumericTable[s[i]] {
			return false
		}
	}
	return true
}

func reverseString(s string) string {
	runes := []rune(s)
	slices.Reverse(runes)
	return string(runes)
}

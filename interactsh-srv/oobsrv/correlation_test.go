package oobsrv

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testCorrelationID = "abcdefghij0123456789"
const testCorrelationID2 = "vutsrqponm9876543210"

// lookupSet returns a lookup function that matches any of the given IDs.
func lookupSet(ids ...string) func(string) bool {
	m := make(map[string]bool)
	for _, id := range ids {
		m[id] = true
	}
	return func(s string) bool { return m[s] }
}

func TestMatchCorrelationID(t *testing.T) {
	t.Parallel()

	// Default cidLength=20, so windowSize=23
	const cidLength = 20
	domains := []string{"example.com"}

	t.Run("tier1_id_with_nonce", func(t *testing.T) {
		lookup := lookupSet(testCorrelationID)
		input := testCorrelationID + "nop.example.com"

		matches := MatchCorrelationID(input, cidLength, domains, lookup)
		require.Len(t, matches, 1)
		assert.Equal(t, testCorrelationID, matches[0].UniqueID)
		assert.Equal(t, testCorrelationID+"nop", matches[0].FullID)
	})

	t.Run("tier2_bare_id_fallback", func(t *testing.T) {
		lookup := lookupSet(testCorrelationID)
		// Bare ID as label (no nonce) - too short for tier1 window
		input := testCorrelationID + ".example.com"

		matches := MatchCorrelationID(input, cidLength, domains, lookup)
		require.Len(t, matches, 1)
		assert.Equal(t, testCorrelationID, matches[0].UniqueID)
		assert.Equal(t, testCorrelationID, matches[0].FullID)
	})

	t.Run("tier1_preempts_tier2", func(t *testing.T) {
		lookup := lookupSet(testCorrelationID)
		// ID appears both with nonce and as bare label
		input := testCorrelationID + "nop." + testCorrelationID + ".example.com"

		matches := MatchCorrelationID(input, cidLength, domains, lookup)
		// finds the nonce match
		require.Len(t, matches, 1)
		assert.Equal(t, testCorrelationID, matches[0].UniqueID)
	})

	t.Run("tier2_kept_per_label", func(t *testing.T) {
		const id1 = "aaaabbbbccccddddeeee"
		const id2 = "11112222333344445555"
		lookup := lookupSet(id1, id2)
		// id1 matches a combined window, id2 is an exact-length bare label.
		input := id1 + "abc." + id2 + ".sub.example.com"

		matches := MatchCorrelationID(input, cidLength, domains, lookup)
		require.Len(t, matches, 2)

		ids := []string{matches[0].UniqueID, matches[1].UniqueID}
		assert.Contains(t, ids, id1)
		assert.Contains(t, ids, id2)
	})

	t.Run("multiple_matches_different_labels", func(t *testing.T) {
		const id1 = "aaaabbbbccccddddeeee"
		const id2 = "11112222333344445555"
		lookup := lookupSet(id1, id2)
		input := id1 + "nop." + id2 + "abc.example.com"

		matches := MatchCorrelationID(input, cidLength, domains, lookup)
		require.Len(t, matches, 2)

		ids := []string{matches[0].UniqueID, matches[1].UniqueID}
		assert.Contains(t, ids, id1)
		assert.Contains(t, ids, id2)
	})

	t.Run("no_match", func(t *testing.T) {
		lookup := lookupSet(testCorrelationID)
		const input = "notaregisteredid12345nonce.example.com"

		matches := MatchCorrelationID(input, cidLength, domains, lookup)
		assert.Empty(t, matches)
	})

	t.Run("empty_input", func(t *testing.T) {
		lookup := lookupSet(testCorrelationID)

		matches := MatchCorrelationID("", cidLength, domains, lookup)
		assert.Empty(t, matches)
	})

	t.Run("nonce_wider_alphabet", func(t *testing.T) {
		lookup := lookupSet(testCorrelationID)
		// Nonce contains w, x, y, z which are outside CID base32 but valid alphanumeric
		input := testCorrelationID + "xyz.example.com"

		matches := MatchCorrelationID(input, cidLength, domains, lookup)
		require.Len(t, matches, 1)
		assert.Equal(t, testCorrelationID, matches[0].UniqueID)
		assert.Equal(t, testCorrelationID+"xyz", matches[0].FullID)
	})

	t.Run("rejects_non_base32_in_cid", func(t *testing.T) {
		lookup := lookupSet(testCorrelationID)
		// Hyphen in the CID portion breaks base32 check
		const input = "abcdefghij012345678-nop.example.com"

		matches := MatchCorrelationID(input, cidLength, domains, lookup)
		assert.Empty(t, matches)
	})

	t.Run("rejects_non_alphanumeric_nonce", func(t *testing.T) {
		lookup := lookupSet(testCorrelationID)
		// Hyphen in the nonce portion breaks alphanumeric check
		input := testCorrelationID + "n-p.example.com"

		matches := MatchCorrelationID(input, cidLength, domains, lookup)
		assert.Empty(t, matches)
	})

	t.Run("case_insensitive", func(t *testing.T) {
		lookup := lookupSet(testCorrelationID)
		const input = "ABCDEFGHIJ0123456789nop.example.com"

		matches := MatchCorrelationID(input, cidLength, domains, lookup)
		require.Len(t, matches, 1)
		assert.Equal(t, testCorrelationID, matches[0].UniqueID)
	})

	t.Run("configurable_cid_length", func(t *testing.T) {
		shortCid := 10
		const id = "abcdefghij"
		lookup := lookupSet(id)
		input := id + "nop.example.com"

		matches := MatchCorrelationID(input, shortCid, domains, lookup)
		require.Len(t, matches, 1)
		assert.Equal(t, id, matches[0].UniqueID)
	})

	t.Run("full_id_multi_label", func(t *testing.T) {
		lookup := lookupSet(testCorrelationID)
		input := testCorrelationID + "nonce.sub.example.com"

		matches := MatchCorrelationID(input, cidLength, domains, lookup)
		require.Len(t, matches, 1)
		assert.Equal(t, testCorrelationID+"nonce.sub", matches[0].FullID)
	})

	t.Run("multi_domain_specific_first", func(t *testing.T) {
		// More-specific domain should match first
		multiDomains := []string{"sub.example.com", "example.com"}
		lookup := lookupSet(testCorrelationID)
		input := testCorrelationID + "nonce.sub.example.com"

		matches := MatchCorrelationID(input, cidLength, multiDomains, lookup)
		require.Len(t, matches, 1)
		assert.Equal(t, testCorrelationID+"nonce", matches[0].FullID)
	})

	t.Run("multiple_cids_same_label", func(t *testing.T) {
		const id1 = "aaaabbbbccccddddeeee"
		const id2 = "11112222333344445555"
		lookup := lookupSet(id1, id2)
		// Both CIDs concatenated with nonces into a single label
		label := id1 + "aaa" + id2 + "bbb"
		input := label + ".example.com"

		matches := MatchCorrelationID(input, cidLength, domains, lookup)
		require.Len(t, matches, 2)
		ids := []string{matches[0].UniqueID, matches[1].UniqueID}
		assert.Contains(t, ids, id1)
		assert.Contains(t, ids, id2)
	})
}

func TestMatchCorrelationIDEverywhere(t *testing.T) {
	t.Parallel()

	const cidLength = 20

	t.Run("splits_by_delimiters", func(t *testing.T) {
		lookup := lookupSet(testCorrelationID)
		// ID embedded across various delimiters
		input := "some\ttext\n\"" + testCorrelationID + "nonce\"\tmore.example.com"

		matches := MatchCorrelationIDEverywhere(input, cidLength, lookup)
		require.Len(t, matches, 1)
		assert.Equal(t, testCorrelationID, matches[0].UniqueID)
	})

	t.Run("single_pass_no_tier2", func(t *testing.T) {
		lookup := lookupSet(testCorrelationID)
		// Bare ID without nonce - would match tier2 in standard mode,
		// but ScanEverywhere uses single-pass with window=23 so it won't match
		input := "prefix." + testCorrelationID + ".example.com"

		matches := MatchCorrelationIDEverywhere(input, cidLength, lookup)
		assert.Empty(t, matches)
	})

	t.Run("matches_in_http_dump", func(t *testing.T) {
		lookup := lookupSet(testCorrelationID)
		dump := "GET / HTTP/1.1\r\nHost: " + testCorrelationID + "nonce.example.com\r\nUser-Agent: test\r\n\r\n"

		matches := MatchCorrelationIDEverywhere(dump, cidLength, lookup)
		require.Len(t, matches, 1)
		assert.Equal(t, testCorrelationID, matches[0].UniqueID)
		// FullID is the matched window (cidLength + minNonceLength = 23 chars)
		assert.Equal(t, testCorrelationID+"non", matches[0].FullID)
	})

	t.Run("deduplicates_same_cid", func(t *testing.T) {
		lookup := lookupSet(testCorrelationID)
		// Same ID appears in multiple chunks - should be deduped
		host := testCorrelationID + "abc." + testCorrelationID + "def.example.com"

		matches := MatchCorrelationIDEverywhere(host, cidLength, lookup)
		assert.Len(t, matches, 1)
	})

	t.Run("consecutive_delimiters_skipped", func(t *testing.T) {
		lookup := lookupSet(testCorrelationID)
		// Consecutive delimiters (dots, tabs) create empty chunks that FieldsFunc skips
		input := "..\t\t" + testCorrelationID + "nop" + "\t\t..example.com"

		matches := MatchCorrelationIDEverywhere(input, cidLength, lookup)
		require.Len(t, matches, 1)
		assert.Equal(t, testCorrelationID, matches[0].UniqueID)
	})

	t.Run("nonce_wider_alphabet", func(t *testing.T) {
		lookup := lookupSet(testCorrelationID)
		input := testCorrelationID + "wxyz"

		matches := MatchCorrelationIDEverywhere(input, cidLength, lookup)
		require.Len(t, matches, 1)
		assert.Equal(t, testCorrelationID, matches[0].UniqueID)
	})

	t.Run("non_base32_cid_skipped", func(t *testing.T) {
		lookup := lookupSet(testCorrelationID)
		// Hyphen in CID portion breaks the base32 check
		const input = "abcdefghij012345678-nop"

		matches := MatchCorrelationIDEverywhere(input, cidLength, lookup)
		assert.Empty(t, matches)
	})

	t.Run("non_alphanumeric_nonce_skipped", func(t *testing.T) {
		lookup := lookupSet(testCorrelationID)
		// Hyphen in nonce portion breaks the alphanumeric check
		input := testCorrelationID + "n-p"

		matches := MatchCorrelationIDEverywhere(input, cidLength, lookup)
		assert.Empty(t, matches)
	})

	t.Run("multiple_distinct_cids", func(t *testing.T) {
		lookup := lookupSet(testCorrelationID, testCorrelationID2)
		input := testCorrelationID + "abc." + testCorrelationID2 + "def"

		matches := MatchCorrelationIDEverywhere(input, cidLength, lookup)
		require.Len(t, matches, 2)
		ids := []string{matches[0].UniqueID, matches[1].UniqueID}
		assert.Contains(t, ids, testCorrelationID)
		assert.Contains(t, ids, testCorrelationID2)
	})
}

func TestMatchLDAPCorrelationID(t *testing.T) {
	t.Parallel()

	const cidLength = 20
	domains := []string{"test.com"}

	t.Run("simple_basedn", func(t *testing.T) {
		lookup := lookupSet(testCorrelationID)
		baseDN := "dc=" + testCorrelationID + "nop,dc=test,dc=com"

		matches := MatchLDAPCorrelationID(baseDN, cidLength, domains, lookup)
		require.Len(t, matches, 1)
		assert.Equal(t, testCorrelationID, matches[0].UniqueID)
		assert.Equal(t, testCorrelationID+"nop", matches[0].FullID)
	})

	t.Run("cid_with_domain_suffix", func(t *testing.T) {
		lookup := lookupSet(testCorrelationID)
		baseDN := "dc=" + testCorrelationID + "nop.test.com,dc=example"

		matches := MatchLDAPCorrelationID(baseDN, cidLength, domains, lookup)
		require.Len(t, matches, 1)
		assert.Equal(t, testCorrelationID, matches[0].UniqueID)
		assert.Equal(t, testCorrelationID+"nop", matches[0].FullID)
	})

	t.Run("bare_cid_tier2", func(t *testing.T) {
		lookup := lookupSet(testCorrelationID)
		baseDN := "dc=" + testCorrelationID + ",dc=test,dc=com"

		matches := MatchLDAPCorrelationID(baseDN, cidLength, domains, lookup)
		require.Len(t, matches, 1)
		assert.Equal(t, testCorrelationID, matches[0].UniqueID)
	})

	t.Run("no_match", func(t *testing.T) {
		lookup := lookupSet(testCorrelationID)
		const baseDN = "dc=something,dc=else"

		matches := MatchLDAPCorrelationID(baseDN, cidLength, domains, lookup)
		assert.Empty(t, matches)
	})

	t.Run("no_domain_in_part", func(t *testing.T) {
		lookup := lookupSet(testCorrelationID)
		// Part is bare CID+nonce without domain suffix
		baseDN := "dc=" + testCorrelationID + "nop,dc=other"

		matches := MatchLDAPCorrelationID(baseDN, cidLength, domains, lookup)
		require.Len(t, matches, 1)
		// No domain suffix to strip, full-id is the whole part
		assert.Equal(t, testCorrelationID+"nop", matches[0].FullID)
	})

	t.Run("same_cid_deduped", func(t *testing.T) {
		lookup := lookupSet(testCorrelationID)
		// Same CID in multiple RDN components - should be deduped
		baseDN := "cn=" + testCorrelationID + "abc,dc=" + testCorrelationID + "def"

		matches := MatchLDAPCorrelationID(baseDN, cidLength, domains, lookup)
		require.Len(t, matches, 1)
		assert.Equal(t, testCorrelationID, matches[0].UniqueID)
	})

	t.Run("multiple_cids", func(t *testing.T) {
		lookup := lookupSet(testCorrelationID, testCorrelationID2)
		baseDN := "cn=" + testCorrelationID + "abc,dc=" + testCorrelationID2 + "def"

		matches := MatchLDAPCorrelationID(baseDN, cidLength, domains, lookup)
		require.Len(t, matches, 2)

		ids := []string{matches[0].UniqueID, matches[1].UniqueID}
		assert.Contains(t, ids, testCorrelationID)
		assert.Contains(t, ids, testCorrelationID2)
	})

	t.Run("case_insensitive", func(t *testing.T) {
		lookup := lookupSet(testCorrelationID)
		baseDN := "DC=" + strings.ToUpper(testCorrelationID+"NOP") + ",DC=TEST,DC=COM"

		matches := MatchLDAPCorrelationID(baseDN, cidLength, domains, lookup)
		require.Len(t, matches, 1)
		assert.Equal(t, testCorrelationID, matches[0].UniqueID)
	})

	t.Run("tier2_independent_per_part", func(t *testing.T) {
		lookup := lookupSet(testCorrelationID, testCorrelationID2)
		// part1 has tier1 match (CID+nonce), part2 has bare CID (tier2-only)
		baseDN := "cn=" + testCorrelationID + "nop,dc=" + testCorrelationID2

		matches := MatchLDAPCorrelationID(baseDN, cidLength, domains, lookup)
		require.Len(t, matches, 2)

		ids := []string{matches[0].UniqueID, matches[1].UniqueID}
		assert.Contains(t, ids, testCorrelationID)
		assert.Contains(t, ids, testCorrelationID2)
	})

	t.Run("whitespace_in_parts", func(t *testing.T) {
		lookup := lookupSet(testCorrelationID)
		baseDN := "cn = " + testCorrelationID + "nop , dc = test"

		matches := MatchLDAPCorrelationID(baseDN, cidLength, domains, lookup)
		require.Len(t, matches, 1)
		assert.Equal(t, testCorrelationID, matches[0].UniqueID)
	})

	t.Run("malformed_basedns_empty", func(t *testing.T) {
		lookup := lookupSet(testCorrelationID)
		for _, baseDN := range []string{"=,=,=", "dc=,dc=", ",,,", ""} {
			matches := MatchLDAPCorrelationID(baseDN, cidLength, domains, lookup)
			assert.Empty(t, matches)
		}
	})
}

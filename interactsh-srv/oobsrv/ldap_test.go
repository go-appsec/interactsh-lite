package oobsrv

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vjeantet/ldapserver"
)

// ldapTestServer starts an LDAP server on an ephemeral port.
// Returns the listener address; cleanup is registered via t.Cleanup.
func ldapTestServer(t *testing.T, srv *Server) string {
	t.Helper()

	mux := ldapserver.NewRouteMux()
	mux.Bind(srv.handleLDAPBind)
	mux.Search(srv.handleLDAPSearch)
	mux.Add(srv.handleLDAPAdd)
	mux.Delete(srv.handleLDAPDelete)
	mux.Modify(srv.handleLDAPModify)
	mux.Compare(srv.handleLDAPCompare)
	mux.Abandon(srv.handleLDAPAbandon)
	mux.Extended(srv.handleLDAPStartTLS()).RequestName(ldapserver.NoticeOfStartTLS)
	mux.Extended(srv.handleLDAPWhoAmI()).RequestName(ldapserver.NoticeOfWhoAmI)
	mux.NotFound(srv.handleLDAPNotFound)

	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()

	ldapSrv := ldapserver.NewServer()
	ldapSrv.Handle(mux)
	go func() { _ = ldapSrv.Serve(ln) }()

	t.Cleanup(func() { ldapSrv.Stop() })
	return addr
}

func TestCaptureLDAPSearchInteraction(t *testing.T) {
	t.Parallel()

	t.Run("stores_correlation_match", func(t *testing.T) {
		srv := testServerWithStorage(t)
		pubKey := &sharedRSAKey.PublicKey
		aesKey, err := srv.storage.Register(t.Context(), testCorrelationID, pubKey, "secret", nil)
		require.NoError(t, err)

		baseDN := "dc=" + testCorrelationID + testNonce + ",dc=test,dc=com"
		rawRequest := fmt.Sprintf("Type=Search\nBaseDn=%s\nFilter=(objectClass=*)\nAttributes=\n", baseDN)

		srv.captureLDAPSearchInteraction(baseDN, rawRequest, "10.0.0.1")

		interactions, err := testGetAndClearInteractions(t, srv.storage, testCorrelationID, "secret")
		require.NoError(t, err)
		require.Len(t, interactions, 1)

		decrypted := decryptTestInteraction(t, interactions[0], aesKey)
		var interaction InteractionType
		require.NoError(t, json.Unmarshal([]byte(decrypted), &interaction))

		assert.Equal(t, "ldap", interaction.Protocol)
		assert.Equal(t, testCorrelationID, interaction.UniqueID)
		assert.Equal(t, testCorrelationID+testNonce, interaction.FullId)
		assert.Equal(t, rawRequest, interaction.RawRequest)
		assert.Equal(t, "10.0.0.1", interaction.RemoteAddress)
		assert.False(t, interaction.Timestamp.IsZero())
	})

	t.Run("no_match_no_storage", func(t *testing.T) {
		srv := testServerWithStorage(t)
		pubKey := &sharedRSAKey.PublicKey
		_, err := srv.storage.Register(t.Context(), testCorrelationID, pubKey, "secret", nil)
		require.NoError(t, err)

		const baseDN = "dc=unrelated,dc=org"
		srv.captureLDAPSearchInteraction(baseDN, "Type=Search\n", "1.2.3.4")

		interactions, err := testGetAndClearInteractions(t, srv.storage, testCorrelationID, "secret")
		require.NoError(t, err)
		assert.Empty(t, interactions)
	})

	t.Run("cid_with_domain_suffix", func(t *testing.T) {
		srv := testServerWithStorage(t)
		pubKey := &sharedRSAKey.PublicKey
		aesKey, err := srv.storage.Register(t.Context(), testCorrelationID, pubKey, "secret", nil)
		require.NoError(t, err)

		baseDN := "dc=" + testCorrelationID + testNonce + ".test.com"
		srv.captureLDAPSearchInteraction(baseDN, "Type=Search\n", "1.2.3.4")

		interactions, err := testGetAndClearInteractions(t, srv.storage, testCorrelationID, "secret")
		require.NoError(t, err)
		require.Len(t, interactions, 1)

		decrypted := decryptTestInteraction(t, interactions[0], aesKey)
		var interaction InteractionType
		require.NoError(t, json.Unmarshal([]byte(decrypted), &interaction))
		assert.Equal(t, testCorrelationID+testNonce, interaction.FullId)
	})
}

func TestCaptureLDAPExtra(t *testing.T) {
	t.Parallel()

	t.Run("stores_in_extra_bucket", func(t *testing.T) {
		srv := testServerWithStorage(t, func(c *Config) {
			c.Auth = true
			c.Token = testToken
			c.LDAP = true
		})

		srv.captureLDAPExtra("Type=Bind\nUser=admin\n", "10.0.0.1")

		data := srv.extraBucket.ReadFrom("consumer1")
		require.Len(t, data, 1)

		var interaction InteractionType
		require.NoError(t, json.Unmarshal(data[0], &interaction))
		assert.Equal(t, "ldap", interaction.Protocol)
		assert.Equal(t, "Type=Bind\nUser=admin\n", interaction.RawRequest)
		assert.Equal(t, "10.0.0.1", interaction.RemoteAddress)
		assert.Empty(t, interaction.UniqueID)
		assert.Empty(t, interaction.FullId)
	})

	t.Run("ldap_disabled_skips_capture", func(t *testing.T) {
		srv := testServerWithStorage(t, func(c *Config) {
			c.LDAP = false
		})

		srv.captureLDAPExtra("Type=Bind\nUser=admin\n", "10.0.0.1")

		assert.Nil(t, srv.extraBucket)
	})
}

func TestLDAPServer(t *testing.T) {
	t.Parallel()

	t.Run("accepts_bind", func(t *testing.T) {
		srv := testServerWithStorage(t)
		addr := ldapTestServer(t, srv)

		conn, err := ldap.DialURL("ldap://" + addr)
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })

		err = conn.Bind("cn=admin", "password")
		assert.NoError(t, err)
	})

	t.Run("search_returns_fake_entry", func(t *testing.T) {
		srv := testServerWithStorage(t)
		addr := ldapTestServer(t, srv)

		conn, err := ldap.DialURL("ldap://" + addr)
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })

		err = conn.Bind("cn=admin", "password")
		require.NoError(t, err)

		result, err := conn.Search(&ldap.SearchRequest{
			BaseDN: "dc=example,dc=com",
			Filter: "(objectClass=*)",
		})
		require.NoError(t, err)
		require.Len(t, result.Entries, 1)

		entry := result.Entries[0]
		assert.Equal(t, "cn=interactsh,dc=example,dc=com", entry.DN)
		assert.Equal(t, []string{"interact@s.h", "interact@s.h"}, entry.GetAttributeValues("mail"))
		assert.Equal(t, []string{"aaa"}, entry.GetAttributeValues("company"))
		assert.Equal(t, []string{"bbbb"}, entry.GetAttributeValues("department"))
		assert.Equal(t, []string{"cccc"}, entry.GetAttributeValues("l"))
		assert.Equal(t, []string{"123456789"}, entry.GetAttributeValues("mobile"))
		assert.Equal(t, []string{"123456789"}, entry.GetAttributeValues("telephoneNumber"))
		assert.Equal(t, []string{"interact"}, entry.GetAttributeValues("cn"))
	})

	t.Run("captures_search_interaction", func(t *testing.T) {
		srv := testServerWithStorage(t)
		pubKey := &sharedRSAKey.PublicKey
		aesKey, err := srv.storage.Register(t.Context(), testCorrelationID, pubKey, "secret", nil)
		require.NoError(t, err)

		addr := ldapTestServer(t, srv)

		conn, err := ldap.DialURL("ldap://" + addr)
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })

		err = conn.Bind("cn=admin", "password")
		require.NoError(t, err)

		baseDN := "dc=" + testCorrelationID + testNonce + ",dc=test,dc=com"
		_, err = conn.Search(&ldap.SearchRequest{
			BaseDN: baseDN,
			Filter: "(objectClass=*)",
		})
		require.NoError(t, err)

		interactions, err := testGetAndClearInteractions(t, srv.storage, testCorrelationID, "secret")
		require.NoError(t, err)
		require.Len(t, interactions, 1)

		decrypted := decryptTestInteraction(t, interactions[0], aesKey)
		var interaction InteractionType
		require.NoError(t, json.Unmarshal([]byte(decrypted), &interaction))

		assert.Equal(t, "ldap", interaction.Protocol)
		assert.Equal(t, testCorrelationID, interaction.UniqueID)
		assert.Contains(t, interaction.RawRequest, "Type=Search")
		assert.Contains(t, interaction.RawRequest, "BaseDn="+baseDN)
	})

	t.Run("full_logging_all_ops", func(t *testing.T) {
		srv := testServerWithStorage(t, func(c *Config) {
			c.Auth = true
			c.Token = testToken
			c.LDAP = true
		})
		addr := ldapTestServer(t, srv)

		conn, err := ldap.DialURL("ldap://" + addr)
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })

		err = conn.Bind("cn=admin", "password")
		require.NoError(t, err)

		_, err = conn.Search(&ldap.SearchRequest{
			BaseDN: "dc=example,dc=com",
			Filter: "(objectClass=*)",
		})
		require.NoError(t, err)

		// Add
		addReq := ldap.NewAddRequest("cn=test,dc=example,dc=com", nil)
		addReq.Attribute("cn", []string{"test"})
		err = conn.Add(addReq)
		require.NoError(t, err)

		// Modify
		modReq := ldap.NewModifyRequest("cn=test,dc=example,dc=com", nil)
		modReq.Add("description", []string{"value"})
		err = conn.Modify(modReq)
		require.NoError(t, err)

		// Delete
		delReq := ldap.NewDelRequest("cn=test,dc=example,dc=com", nil)
		err = conn.Del(delReq)
		require.NoError(t, err)

		// Compare
		_, err = conn.Compare("cn=test,dc=example,dc=com", "cn", "test")
		require.NoError(t, err)

		data := srv.extraBucket.ReadFrom("consumer1")
		require.GreaterOrEqual(t, len(data), 6)

		// Verify operation types in extra bucket
		var ops []string
		for _, d := range data {
			var interaction InteractionType
			if json.Unmarshal(d, &interaction) == nil {
				for _, line := range strings.Split(interaction.RawRequest, "\n") {
					if strings.HasPrefix(line, "Type=") {
						ops = append(ops, line)
						break
					}
				}
			}
		}
		assert.Contains(t, ops, "Type=Bind")
		assert.Contains(t, ops, "Type=Search")
		assert.Contains(t, ops, "Type=Add")
		assert.Contains(t, ops, "Type=Modify")
		assert.Contains(t, ops, "Type=Delete")
		assert.Contains(t, ops, "Type=Compare")
	})

	t.Run("starttls_with_config", func(t *testing.T) {
		srv := testServerWithStorage(t)
		srv.tlsConfig = testTLSConfig(t)
		addr := ldapTestServer(t, srv)

		conn, err := ldap.DialURL("ldap://" + addr)
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })

		require.NoError(t, conn.StartTLS(tlsInsecureConfig()))

		// Verify LDAP works after TLS upgrade
		require.NoError(t, conn.Bind("cn=admin", "password"))
	})

	t.Run("starttls_nil_config", func(t *testing.T) {
		srv := testServerWithStorage(t)
		srv.tlsConfig = nil
		addr := ldapTestServer(t, srv)

		conn, err := ldap.DialURL("ldap://" + addr)
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })

		err = conn.StartTLS(tlsInsecureConfig())
		assert.Error(t, err)
	})

	t.Run("modify_operation_types", func(t *testing.T) {
		srv := testServerWithStorage(t, func(c *Config) {
			c.Auth = true
			c.Token = testToken
			c.LDAP = true
		})
		addr := ldapTestServer(t, srv)

		conn, err := ldap.DialURL("ldap://" + addr)
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })

		err = conn.Bind("cn=admin", "password")
		require.NoError(t, err)

		modReq := ldap.NewModifyRequest("cn=test,dc=example,dc=com", nil)
		modReq.Add("description", []string{"added"})
		modReq.Delete("obsolete", []string{"removed"})
		modReq.Replace("status", []string{"replaced"})
		err = conn.Modify(modReq)
		require.NoError(t, err)

		data := srv.extraBucket.ReadFrom("consumer1")
		// Find the Modify interaction
		var modRaw string
		for _, d := range data {
			var interaction InteractionType
			if json.Unmarshal(d, &interaction) == nil && strings.Contains(interaction.RawRequest, "Type=Modify") {
				modRaw = interaction.RawRequest
				break
			}
		}
		require.NotEmpty(t, modRaw)
		assert.Contains(t, modRaw, "Operation=Add Attribute=description Values=[added]")
		assert.Contains(t, modRaw, "Operation=Delete Attribute=obsolete Values=[removed]")
		assert.Contains(t, modRaw, "Operation=Replace Attribute=status Values=[replaced]")
	})

	t.Run("add_attribute_formatting", func(t *testing.T) {
		srv := testServerWithStorage(t, func(c *Config) {
			c.Auth = true
			c.Token = testToken
			c.LDAP = true
		})
		addr := ldapTestServer(t, srv)

		conn, err := ldap.DialURL("ldap://" + addr)
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })

		err = conn.Bind("cn=admin", "password")
		require.NoError(t, err)

		addReq := ldap.NewAddRequest("cn=user,dc=example,dc=com", nil)
		addReq.Attribute("cn", []string{"user"})
		addReq.Attribute("mail", []string{"user@example.com"})
		addReq.Attribute("objectClass", []string{"top", "person"})
		err = conn.Add(addReq)
		require.NoError(t, err)

		data := srv.extraBucket.ReadFrom("consumer1")
		var addRaw string
		for _, d := range data {
			var interaction InteractionType
			if json.Unmarshal(d, &interaction) == nil && strings.Contains(interaction.RawRequest, "Type=Add") {
				addRaw = interaction.RawRequest
				break
			}
		}
		require.NotEmpty(t, addRaw)
		assert.Contains(t, addRaw, "Attribute Name=cn Attribute Value=user")
		assert.Contains(t, addRaw, "Attribute Name=mail Attribute Value=user@example.com")
		assert.Contains(t, addRaw, "Attribute Name=objectClass Attribute Value=top")
		assert.Contains(t, addRaw, "Attribute Name=objectClass Attribute Value=person")
	})

	t.Run("search_attributes_in_request", func(t *testing.T) {
		srv := testServerWithStorage(t, func(c *Config) {
			c.Auth = true
			c.Token = testToken
			c.LDAP = true
		})
		addr := ldapTestServer(t, srv)

		conn, err := ldap.DialURL("ldap://" + addr)
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })

		err = conn.Bind("cn=admin", "password")
		require.NoError(t, err)

		_, err = conn.Search(&ldap.SearchRequest{
			BaseDN:     "dc=example,dc=com",
			Filter:     "(objectClass=*)",
			Attributes: []string{"cn", "mail", "uid"},
		})
		require.NoError(t, err)

		data := srv.extraBucket.ReadFrom("consumer1")
		var searchRaw string
		for _, d := range data {
			var interaction InteractionType
			if json.Unmarshal(d, &interaction) == nil && strings.Contains(interaction.RawRequest, "Type=Search") {
				searchRaw = interaction.RawRequest
				break
			}
		}
		require.NotEmpty(t, searchRaw)
		assert.Contains(t, searchRaw, "Attributes=cn, mail, uid")
	})

	t.Run("concurrent_search_same_cid", func(t *testing.T) {
		srv := testServerWithStorage(t, func(c *Config) {
			c.Auth = true
			c.Token = testToken
			c.LDAP = true
		})
		pubKey := &sharedRSAKey.PublicKey

		_, err := srv.storage.Register(t.Context(), testCorrelationID, pubKey, "secret", nil)
		require.NoError(t, err)

		addr := ldapTestServer(t, srv)

		var wg sync.WaitGroup
		for i := range 5 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				conn, err := ldap.DialURL("ldap://" + addr)
				if !assert.NoError(t, err) {
					return
				}
				defer func() { _ = conn.Close() }()

				if err = conn.Bind("cn=admin", "password"); !assert.NoError(t, err) {
					return
				}
				nonce := fmt.Sprintf("%03d", i)
				baseDN := fmt.Sprintf("dc=%s%s,dc=test,dc=com", testCorrelationID, nonce)
				_, err = conn.Search(&ldap.SearchRequest{
					BaseDN: baseDN,
					Filter: "(objectClass=*)",
				})
				assert.NoError(t, err)
			}()
		}
		wg.Wait()

		interactions, err := testGetAndClearInteractions(t, srv.storage, testCorrelationID, "secret")
		require.NoError(t, err)
		assert.Len(t, interactions, 5)
	})

	t.Run("generic_extended_returns_success", func(t *testing.T) {
		srv := testServerWithStorage(t)
		addr := ldapTestServer(t, srv)

		conn, err := ldap.DialURL("ldap://" + addr)
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })

		err = conn.Bind("cn=admin", "password")
		require.NoError(t, err)
		countAfterBind := srv.ldapCount.Load()

		// Send an arbitrary extended operation (not StartTLS or WhoAmI)
		extReq := ldap.NewExtendedRequest("1.2.3.4.5.6.7.8.9", nil)
		_, err = conn.Extended(extReq)
		require.NoError(t, err)

		assert.Greater(t, srv.ldapCount.Load(), countAfterBind)
	})

	t.Run("generic_extended_full_logging", func(t *testing.T) {
		srv := testServerWithStorage(t, func(c *Config) {
			c.Auth = true
			c.Token = testToken
			c.LDAP = true
		})
		addr := ldapTestServer(t, srv)

		conn, err := ldap.DialURL("ldap://" + addr)
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })

		err = conn.Bind("cn=admin", "password")
		require.NoError(t, err)

		extReq := ldap.NewExtendedRequest("1.2.3.4.5.6.7.8.9", nil)
		_, err = conn.Extended(extReq)
		require.NoError(t, err)

		data := srv.extraBucket.ReadFrom("consumer1")
		var found bool
		for _, d := range data {
			var interaction InteractionType
			if json.Unmarshal(d, &interaction) == nil && strings.Contains(interaction.RawRequest, "Type=Extended") {
				assert.Contains(t, interaction.RawRequest, "Name=1.2.3.4.5.6.7.8.9")
				found = true
				break
			}
		}
		assert.True(t, found)
	})

	t.Run("whoami_extended_operation", func(t *testing.T) {
		srv := testServerWithStorage(t, func(c *Config) {
			c.Auth = true
			c.Token = testToken
			c.LDAP = true
		})

		addr := ldapTestServer(t, srv)

		conn, err := ldap.DialURL("ldap://" + addr)
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })

		err = conn.Bind("cn=admin", "password")
		require.NoError(t, err)
		countAfterBind := srv.ldapCount.Load()

		whoAmIReq := ldap.NewExtendedRequest("1.3.6.1.4.1.4203.1.11.3", nil)
		_, err = conn.Extended(whoAmIReq)
		require.NoError(t, err)

		assert.Greater(t, srv.ldapCount.Load(), countAfterBind)
	})
}

func TestStartLDAP(t *testing.T) {
	t.Parallel()

	t.Run("bind_failure_non_fatal", func(t *testing.T) {
		srv := testServerWithStorage(t)
		srv.cfg.ListenIP = testListenIP

		// Occupy a port
		var lc net.ListenConfig
		ln, err := lc.Listen(t.Context(), "tcp", testListenIP+":0")
		require.NoError(t, err)
		t.Cleanup(func() { _ = ln.Close() })
		srv.cfg.LDAPPort = ln.Addr().(*net.TCPAddr).Port

		serviceCount := len(srv.services)
		srv.startLDAP()

		assert.Len(t, srv.services, serviceCount)
	})
}

func tlsInsecureConfig() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true}
}

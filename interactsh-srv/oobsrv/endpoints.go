package oobsrv

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-appsec/interactsh-lite/oobclient"
)

// jsonErrorKey is the JSON field key for error responses.
const jsonErrorKey = "error"

// registerRequest is the POST /register JSON body.
type registerRequest struct {
	PublicKey     string                    `json:"public-key"`
	SecretKey     string                    `json:"secret-key"`
	CorrelationID string                    `json:"correlation-id"`
	Response      *oobclient.ResponseConfig `json:"response,omitempty"`
}

// deregisterRequest is the POST /deregister JSON body.
type deregisterRequest struct {
	CorrelationID string `json:"correlation-id"`
	SecretKey     string `json:"secret-key"`
}

// pollResponse is the GET /poll JSON response.
type pollResponse struct {
	Data    []string `json:"data"`
	AESKey  string   `json:"aes_key"`
	Extra   []string `json:"extra"`
	TLDData []string `json:"tlddata,omitempty"`
}

// writeJSON writes v as JSON with the given status code.
func (s *Server) writeJSON(w http.ResponseWriter, status int, v any) {
	data, err := json.Marshal(v)
	if err != nil {
		s.logger.Error("failed to marshal JSON response", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(data)
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, map[string]string{
			jsonErrorKey: fmt.Sprintf("could not decode json body: %v", err),
		})
		return
	}

	if req.SecretKey == "" {
		s.writeJSON(w, http.StatusBadRequest, map[string]string{
			jsonErrorKey: "secret-key must not be empty",
		})
		return
	}

	if len(req.CorrelationID) < s.cfg.CorrelationIdLength {
		s.writeJSON(w, http.StatusBadRequest, map[string]string{
			jsonErrorKey: fmt.Sprintf("correlation-id must be at least %d characters", s.cfg.CorrelationIdLength),
		})
		return
	}
	if len(req.CorrelationID) > s.cfg.CorrelationIdLength {
		req.CorrelationID = req.CorrelationID[:s.cfg.CorrelationIdLength]
	}

	if !isCIDBase32(req.CorrelationID) {
		s.writeJSON(w, http.StatusBadRequest, map[string]string{
			jsonErrorKey: "correlation-id contains invalid characters",
		})
		return
	}

	pubKey, err := ParsePublicKey(req.PublicKey)
	if err != nil {
		s.writeJSON(w, http.StatusBadRequest, map[string]string{
			jsonErrorKey: fmt.Sprintf("could not decode public key: %v", err),
		})
		return
	}

	if req.Response != nil {
		if !s.cfg.DynamicResp {
			s.writeJSON(w, http.StatusBadRequest, map[string]string{
				jsonErrorKey: "server does not support response configuration (--dynamic-resp not enabled)",
			})
			return
		} else if !s.cfg.Auth && !req.Response.IsAllowedUnauthenticated() {
			s.writeJSON(w, http.StatusBadRequest, map[string]string{
				jsonErrorKey: "unauthenticated servers only allow 302/307 redirects with a Location header",
			})
			return
		}
	}

	_, err = s.storage.Register(r.Context(), req.CorrelationID, pubKey, req.SecretKey, req.Response)
	if err != nil {
		s.writeJSON(w, http.StatusBadRequest, map[string]string{
			jsonErrorKey: err.Error(),
		})
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]string{
		"message": "registration successful",
	})
}

func (s *Server) handlePoll(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	secret := r.URL.Query().Get("secret")

	if len(id) < s.cfg.CorrelationIdLength {
		s.writeJSON(w, http.StatusBadRequest, map[string]string{
			jsonErrorKey: fmt.Sprintf("correlation-id must be at least %d characters", s.cfg.CorrelationIdLength),
		})
		return
	}
	if len(id) > s.cfg.CorrelationIdLength {
		id = id[:s.cfg.CorrelationIdLength]
	}

	handle, err := s.storage.GetSession(id, secret)
	if err != nil {
		s.writeJSON(w, http.StatusBadRequest, map[string]string{
			jsonErrorKey: err.Error(),
		})
		return
	}

	interactions, err := handle.GetAndClearInteractions()
	if err != nil {
		s.writeJSON(w, http.StatusBadRequest, map[string]string{
			jsonErrorKey: err.Error(),
		})
		return
	}

	data := make([]string, 0)
	var aesKeyStr string

	if len(interactions) > 0 {
		data = make([]string, len(interactions))
		for i, b := range interactions {
			data[i] = base64.StdEncoding.EncodeToString(b)
		}

		aesKeyStr, err = EncryptAESKey(handle.AESKey(), handle.PublicKey())
		if err != nil {
			s.logger.Error("failed to encrypt AES key", "error", err)
			s.writeJSON(w, http.StatusInternalServerError, map[string]string{
				jsonErrorKey: "encryption failed",
			})
			return
		}
	}

	var extra []string
	if s.extraBucket != nil {
		if raw := s.extraBucket.ReadFrom(id); len(raw) > 0 {
			extra = make([]string, len(raw))
			for i, b := range raw {
				extra[i] = string(b)
			}
		}
	}

	var tldData []string
	if s.cfg.Wildcard {
		for _, domain := range s.cfg.Domains {
			if bucket, ok := s.tldBuckets[domain]; ok {
				if raw := bucket.ReadFrom(id); len(raw) > 0 {
					for _, b := range raw {
						tldData = append(tldData, string(b))
					}
				}
			}
		}
	}

	s.writeJSON(w, http.StatusOK, pollResponse{
		Data:    data,
		AESKey:  aesKeyStr,
		Extra:   extra,
		TLDData: tldData,
	})
}

func (s *Server) handleDeregister(w http.ResponseWriter, r *http.Request) {
	var req deregisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSON(w, http.StatusBadRequest, map[string]string{
			jsonErrorKey: fmt.Sprintf("could not decode json body: %v", err),
		})
		return
	}

	if len(req.CorrelationID) < s.cfg.CorrelationIdLength {
		s.writeJSON(w, http.StatusBadRequest, map[string]string{
			jsonErrorKey: fmt.Sprintf("correlation-id must be at least %d characters", s.cfg.CorrelationIdLength),
		})
		return
	}
	if len(req.CorrelationID) > s.cfg.CorrelationIdLength {
		req.CorrelationID = req.CorrelationID[:s.cfg.CorrelationIdLength]
	}

	if err := s.storage.Delete(req.CorrelationID, req.SecretKey); err != nil {
		s.writeJSON(w, http.StatusBadRequest, map[string]string{
			jsonErrorKey: err.Error(),
		})
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]string{
		"message": "deregistration successful",
	})
}

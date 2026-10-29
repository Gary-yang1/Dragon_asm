package engine

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"baiyan/internal/networkenrich"
)

const maxNetworkEnrichmentBody = 128 << 10

type NetworkEnricher interface {
	Enrich(context.Context, networkenrich.Request) (networkenrich.Response, error)
}

func (h *Handler) enrichNetwork(w http.ResponseWriter, r *http.Request) {
	if !h.authorized(r) {
		writeError(w, http.StatusUnauthorized, "INVALID_AUTH", "invalid engine authentication")
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method not allowed")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxNetworkEnrichmentBody)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var request networkenrich.Request
	if err := decoder.Decode(&request); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, "PAYLOAD_TOO_LARGE", "network enrichment request exceeds 128 KiB")
			return
		}
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "invalid network enrichment request")
		return
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "request must contain one JSON object")
		return
	}
	if _, err := networkenrich.Validate(request); err != nil {
		writeError(w, http.StatusUnprocessableEntity, "INVALID_REQUEST", err.Error())
		return
	}
	result, err := h.networkEnricher.Enrich(r.Context(), request)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "ENRICHMENT_UNAVAILABLE", "network enrichment is temporarily unavailable")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, result)
}

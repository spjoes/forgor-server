package httpapi

import (
	"encoding/json"
	"net/http"
	"strconv"

	"forgor-server/internal/apierror"

	"github.com/google/uuid"
)

func parseJSON(r *http.Request, v interface{}) *apierror.APIError {
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(v); err != nil {
		return apierror.BadRequest("invalid_json", "failed to parse JSON: "+err.Error())
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func parseUUID(s string) (uuid.UUID, error) {
	return uuid.Parse(s)
}

func parseUint64(s string) (uint64, error) {
	return strconv.ParseUint(s, 10, 64)
}

package transport

import (
	"encoding/json"
	stdio "io"
	"net/http"
)

type ErrorResponse struct {
	Error string `json:"error"`
}

func ReadJSON(r *http.Request, dst any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(r.Body)
	return dec.Decode(dst)
}

func ReadJSONBody(body stdio.Reader, dst any) error {
	dec := json.NewDecoder(body)
	return dec.Decode(dst)
}

func WriteJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func WriteError(w http.ResponseWriter, status int, message string) {
	WriteJSON(w, status, ErrorResponse{Error: message})
}

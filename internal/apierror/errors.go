package apierror

import (
	"encoding/json"
	"fmt"
	"net/http"
)

type APIError struct {
	StatusCode int    `json:"-"`
	Code       string `json:"code"`
	Message    string `json:"message"`
}

func (e *APIError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func (e *APIError) WriteJSON(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(e.StatusCode)
	json.NewEncoder(w).Encode(e)
}

func BadRequest(code, message string) *APIError {
	return &APIError{
		StatusCode: http.StatusBadRequest,
		Code:       code,
		Message:    message,
	}
}

func Unauthorized(message string) *APIError {
	return &APIError{
		StatusCode: http.StatusUnauthorized,
		Code:       "unauthorized",
		Message:    message,
	}
}

func Forbidden(message string) *APIError {
	return &APIError{
		StatusCode: http.StatusForbidden,
		Code:       "forbidden",
		Message:    message,
	}
}

func NotFound(resource string) *APIError {
	return &APIError{
		StatusCode: http.StatusNotFound,
		Code:       "not_found",
		Message:    fmt.Sprintf("%s not found", resource),
	}
}

func Conflict(message string) *APIError {
	return &APIError{
		StatusCode: http.StatusConflict,
		Code:       "conflict",
		Message:    message,
	}
}

func TooManyRequests(message string) *APIError {
	return &APIError{
		StatusCode: http.StatusTooManyRequests,
		Code:       "rate_limit_exceeded",
		Message:    message,
	}
}

func InternalError() *APIError {
	return &APIError{
		StatusCode: http.StatusInternalServerError,
		Code:       "internal_error",
		Message:    "An internal error occurred",
	}
}

func PayloadTooLarge(message string) *APIError {
	return &APIError{
		StatusCode: http.StatusRequestEntityTooLarge,
		Code:       "payload_too_large",
		Message:    message,
	}
}

func InvalidDeviceID() *APIError {
	return BadRequest("invalid_device_id", "device_id must be 64 lowercase hex characters")
}

func InvalidSignature() *APIError {
	return BadRequest("invalid_signature", "signature verification failed")
}

func InvalidDeviceBundle() *APIError {
	return BadRequest("invalid_device_bundle", "device bundle validation failed")
}

func InvalidNonce() *APIError {
	return BadRequest("invalid_nonce", "nonce must be 24 bytes")
}

func InvalidHash() *APIError {
	return BadRequest("invalid_hash", "hash must be 32 bytes")
}

func InvalidPublicKey() *APIError {
	return BadRequest("invalid_public_key", "public key must be 32 bytes")
}

func InvalidUUID(field string) *APIError {
	return BadRequest("invalid_uuid", fmt.Sprintf("invalid UUID for field: %s", field))
}

func ChainValidationFailed(message string) *APIError {
	return BadRequest("chain_validation_failed", message)
}

func MembershipRequired() *APIError {
	return Forbidden("device is not a member of this vault")
}

func OwnerRequired() *APIError {
	return Forbidden("only the vault owner can perform this action")
}

func InviteAlreadyUsed() *APIError {
	return Conflict("invite has already been used")
}

func DuplicateDevice() *APIError {
	return Conflict("device already registered with different keys")
}

func EventChainBroken() *APIError {
	return BadRequest("event_chain_broken", "event counter or prev_hash does not match expected chain")
}

func MembershipChainBroken() *APIError {
	return BadRequest("membership_chain_broken", "member_seq or prev_hash does not match expected chain")
}

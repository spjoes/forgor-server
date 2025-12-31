package httpapi

import (
	"net/http"
	"strings"
	"time"

	"forgor-server/internal/config"
	"forgor-server/internal/db"
	"forgor-server/internal/storage"
	"forgor-server/internal/validation"
)

type Server struct {
	db     *db.DB
	config *config.Config

	devices      *storage.DevicesRepository
	vaults       *storage.VaultsRepository
	memberEvents *storage.MemberEventsRepository
	invites      *storage.InvitesRepository
	events       *storage.EventsRepository
	keyUpdates   *storage.KeyUpdatesRepository
	snapshots    *storage.SnapshotsRepository

	deviceValidator     *validation.DeviceValidator
	membershipValidator *validation.MembershipValidator
	invitesValidator    *validation.InvitesValidator
	eventsValidator     *validation.EventsValidator
	keyUpdatesValidator *validation.KeyUpdatesValidator
	snapshotsValidator  *validation.SnapshotsValidator

	rateLimiter *IPRateLimiter
}

func NewServer(database *db.DB, cfg *config.Config) *Server {
	devices := storage.NewDevicesRepository(database)
	vaults := storage.NewVaultsRepository(database)
	memberEvents := storage.NewMemberEventsRepository(database)
	invites := storage.NewInvitesRepository(database)
	events := storage.NewEventsRepository(database)
	keyUpdates := storage.NewKeyUpdatesRepository(database)
	snapshots := storage.NewSnapshotsRepository(database)

	return &Server{
		db:     database,
		config: cfg,

		devices:      devices,
		vaults:       vaults,
		memberEvents: memberEvents,
		invites:      invites,
		events:       events,
		keyUpdates:   keyUpdates,
		snapshots:    snapshots,

		deviceValidator:     validation.NewDeviceValidator(devices),
		membershipValidator: validation.NewMembershipValidator(vaults, memberEvents, invites, devices),
		invitesValidator:    validation.NewInvitesValidator(vaults, invites, devices),
		eventsValidator:     validation.NewEventsValidator(vaults, events),
		keyUpdatesValidator: validation.NewKeyUpdatesValidator(vaults, keyUpdates, invites),
		snapshotsValidator:  validation.NewSnapshotsValidator(vaults, snapshots, invites),

		rateLimiter: NewIPRateLimiter(cfg.RateLimitRequestsPerSecond, cfg.RateLimitBurst),
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", s.handleHealth)

	mux.HandleFunc("POST /v1/devices/register", s.handleDeviceRegister)
	mux.HandleFunc("GET /v1/devices/{device_id}", s.handleDeviceGet)

	mux.HandleFunc("POST /v1/vaults/{vault_id}/invites", s.handleInviteCreate)
	mux.HandleFunc("GET /v1/invites", s.handleInvitesList)
	mux.HandleFunc("POST /v1/invites/{invite_id}/claim", s.handleInviteClaim)
	mux.HandleFunc("GET /v1/invite_claims", s.handleInviteClaimsList)

	mux.HandleFunc("POST /v1/vaults/{vault_id}/member_events", s.handleMemberEventCreate)
	mux.HandleFunc("GET /v1/vaults/{vault_id}/member_events", s.handleMemberEventsList)
	mux.HandleFunc("GET /v1/vaults/{vault_id}/members", s.handleVaultMembersList)

	mux.HandleFunc("POST /v1/vaults/{vault_id}/events", s.handleEventCreate)
	mux.HandleFunc("GET /v1/vaults/{vault_id}/events", s.handleEventsList)

	mux.HandleFunc("POST /v1/vaults/{vault_id}/key_updates", s.handleKeyUpdateCreate)
	mux.HandleFunc("GET /v1/key_updates", s.handleKeyUpdatesList)
	mux.HandleFunc("POST /v1/vaults/{vault_id}/key_update_acks", s.handleKeyUpdateAck)

	mux.HandleFunc("POST /v1/vaults/{vault_id}/snapshots", s.handleSnapshotCreate)
	mux.HandleFunc("GET /v1/vaults/{vault_id}/snapshots/latest", s.handleSnapshotLatest)

	handler := Chain(mux,
		RecoveryMiddleware,
		RequestIDMiddleware,
		LoggingMiddleware,
		SecurityHeadersMiddleware,
		MaxBodySizeMiddleware(s.config.MaxRequestBodySize),
		RateLimitMiddleware(s.rateLimiter),
		TimeoutMiddleware(30*time.Second),
	)

	return handler
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}

func getPathParam(r *http.Request, name string) string {
	return r.PathValue(name)
}

func getQueryParam(r *http.Request, name string) string {
	return r.URL.Query().Get(name)
}

func extractVaultID(r *http.Request) ([]byte, error) {
	vaultIDStr := getPathParam(r, "vault_id")
	vaultIDStr = strings.ToLower(vaultIDStr)

	parsed, err := parseUUID(vaultIDStr)
	if err != nil {
		return nil, err
	}
	return parsed[:], nil
}

package httpapi

import (
	"net/http"

	"forgor-server/internal/apierror"
	"forgor-server/internal/logging"
	"forgor-server/internal/models"
)

func (s *Server) handleDeviceRegister(w http.ResponseWriter, r *http.Request) {
	var bundle models.DeviceBundle
	if err := parseJSON(r, &bundle); err != nil {
		logging.FromContext(r.Context()).Info("device register parse error", "error", err.Message)
		err.WriteJSON(w)
		return
	}

	ctx := r.Context()

	if apiErr := s.deviceValidator.ValidateBundle(ctx, &bundle); apiErr != nil {
		logging.FromContext(ctx).Info("device register validation error", "error", apiErr.Message, "code", apiErr.Code)
		apiErr.WriteJSON(w)
		return
	}

	if apiErr := s.deviceValidator.CheckImmutability(ctx, &bundle); apiErr != nil {
		apiErr.WriteJSON(w)
		return
	}

	existing, err := s.devices.Get(ctx, string(bundle.DeviceID))
	if err != nil {
		apierror.InternalError().WriteJSON(w)
		return
	}

	if existing != nil {
		writeJSON(w, http.StatusOK, bundle)
		return
	}

	if err := s.devices.Create(ctx, &bundle); err != nil {
		apierror.InternalError().WriteJSON(w)
		return
	}

	writeJSON(w, http.StatusCreated, bundle)
}

func (s *Server) handleDeviceGet(w http.ResponseWriter, r *http.Request) {
	deviceID := getPathParam(r, "device_id")

	did := models.DeviceID(deviceID)
	if err := did.Validate(); err != nil {
		apierror.InvalidDeviceID().WriteJSON(w)
		return
	}

	device, err := s.devices.Get(r.Context(), deviceID)
	if err != nil {
		apierror.InternalError().WriteJSON(w)
		return
	}

	if device == nil {
		apierror.NotFound("device").WriteJSON(w)
		return
	}

	response := models.DeviceBundle{
		DeviceID:        models.DeviceID(device.DeviceID),
		DevicePubkeySign: device.DevicePubkeySign,
		DevicePubkeyBox:  device.DevicePubkeyBox,
		DeviceBundleSig:  device.DeviceBundleSig,
	}

	writeJSON(w, http.StatusOK, response)
}

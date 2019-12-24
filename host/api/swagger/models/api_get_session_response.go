// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	strfmt "github.com/go-openapi/strfmt"

	"github.com/go-openapi/swag"
)

// APIGetSessionResponse api get session response
// swagger:model apiGetSessionResponse
type APIGetSessionResponse struct {

	// host
	Host string `json:"host,omitempty"`

	// session id
	SessionID string `json:"session_id,omitempty"`
}

// Validate validates this api get session response
func (m *APIGetSessionResponse) Validate(formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *APIGetSessionResponse) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *APIGetSessionResponse) UnmarshalBinary(b []byte) error {
	var res APIGetSessionResponse
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
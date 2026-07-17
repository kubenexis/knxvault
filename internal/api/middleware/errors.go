// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"

	"github.com/kubenexis/knxvault/internal/api/dto"
	"github.com/kubenexis/knxvault/internal/domain/common"
)

// ErrorHandler maps domain errors to standardized API responses.
func ErrorHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
		if len(c.Errors) == 0 {
			return
		}

		err := c.Errors.Last().Err
		status, code, message := mapError(err)
		requestID, _ := c.Get("request_id")
		c.JSON(status, dto.ErrorResponse{
			ErrorCode: string(code),
			Message:   message,
			RequestID: requestIDString(requestID),
			Timestamp: time.Now().UTC(),
		})
	}
}

func mapError(err error) (int, common.ErrorCode, string) {
	var kvErr *common.KNXVaultError
	if errors.As(err, &kvErr) {
		switch kvErr.Code {
		case common.ErrCodeValidation:
			return http.StatusBadRequest, kvErr.Code, kvErr.Message
		case common.ErrCodeUnauthorized:
			return http.StatusUnauthorized, kvErr.Code, kvErr.Message
		case common.ErrCodeForbidden:
			return http.StatusForbidden, kvErr.Code, kvErr.Message
		case common.ErrCodeNotFound:
			return http.StatusNotFound, kvErr.Code, kvErr.Message
		default:
			return http.StatusInternalServerError, kvErr.Code, kvErr.Message
		}
	}
	var validationErrs validator.ValidationErrors
	if errors.As(err, &validationErrs) {
		return http.StatusBadRequest, common.ErrCodeValidation, "invalid request"
	}
	return http.StatusInternalServerError, common.ErrCodeInternal, "internal server error"
}

func requestIDString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

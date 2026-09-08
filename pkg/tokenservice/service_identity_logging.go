// Copyright © 2026 OpenCHAMI a Series of LF Projects, LLC
//
// SPDX-License-Identifier: MIT

package tokenservice

import (
	"net/http"

	"github.com/rs/zerolog/log"
)

type serviceIdentityLogContext struct {
	Request         *http.Request
	StatusCode      int
	FailureCategory LogFailureCategory
	FailureStage    string
	Subject         string
	Err             error
}

func logServiceIdentityFailure(ctx serviceIdentityLogContext) {
	event := log.Warn().
		Str(string(LogFieldComponent), "tokenservice").
		Str(string(LogFieldHandler), string(LogHandlerServiceIdentitySession)).
		Str(string(LogFieldAuditEvent), string(LogEventServiceIdentitySessionFailed)).
		Str(string(LogFieldClientIP), exchangeClientIP(ctx.Request)).
		Int("status_code", ctx.StatusCode).
		Str(string(LogFieldFailureCategory), string(ctx.FailureCategory)).
		Str(string(LogFieldFailureStage), ctx.FailureStage)

	if ctx.Subject != "" {
		event = event.Str(string(LogFieldSubject), ctx.Subject)
	}
	if ctx.Err != nil {
		event = event.Err(ctx.Err)
	}

	event.Msg(string(LogEventServiceIdentitySessionFailed))
}

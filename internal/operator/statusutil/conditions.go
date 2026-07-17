// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

// Package statusutil helps set Ready/Issuing conditions.
package statusutil

import (
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1alpha1 "github.com/kubenexis/knxvault/internal/operator/apis/v1alpha1"
)

// SetCondition upserts a condition by type.
func SetCondition(conds []v1alpha1.Condition, typ, status, reason, message string) []v1alpha1.Condition {
	now := metav1.NewTime(time.Now().UTC())
	for i := range conds {
		if conds[i].Type == typ {
			if conds[i].Status != status || conds[i].Reason != reason {
				conds[i].LastTransitionTime = now
			}
			conds[i].Status = status
			conds[i].Reason = reason
			conds[i].Message = message
			return conds
		}
	}
	return append(conds, v1alpha1.Condition{
		Type:               typ,
		Status:             status,
		Reason:             reason,
		Message:            message,
		LastTransitionTime: now,
	})
}

// ReadyTrue marks Ready=True.
func ReadyTrue(conds []v1alpha1.Condition, reason, msg string) []v1alpha1.Condition {
	return SetCondition(conds, v1alpha1.ConditionReady, "True", reason, msg)
}

// ReadyFalse marks Ready=False.
func ReadyFalse(conds []v1alpha1.Condition, reason, msg string) []v1alpha1.Condition {
	return SetCondition(conds, v1alpha1.ConditionReady, "False", reason, msg)
}

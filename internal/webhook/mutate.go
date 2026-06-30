// Package webhook implements Kubernetes admission hooks for KNXVault.
package webhook

import (
	"encoding/json"
	"fmt"
	"strings"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	annotationInject         = "knxvault.io/inject"
	annotationSecretProvider = "knxvault.io/secret-provider-class" // #nosec G101 -- K8s annotation key
	annotationMountPath      = "knxvault.io/inject-mount-path"
	defaultMountPath         = "/mnt/knxvault-secrets"
	csiDriverName            = "secrets-store.csi.k8s.io"
	defaultVolumeName        = "knxvault-secrets"
)

// MutatePod injects a Secrets Store CSI volume when knxvault.io/inject=true.
func MutatePod(pod *corev1.Pod) (bool, error) {
	if pod == nil {
		return false, fmt.Errorf("pod is nil")
	}
	if pod.Annotations == nil || strings.ToLower(strings.TrimSpace(pod.Annotations[annotationInject])) != "true" {
		return false, nil
	}
	spc := strings.TrimSpace(pod.Annotations[annotationSecretProvider])
	if spc == "" {
		return false, fmt.Errorf("%s annotation is required when %s=true", annotationSecretProvider, annotationInject)
	}
	mountPath := strings.TrimSpace(pod.Annotations[annotationMountPath])
	if mountPath == "" {
		mountPath = defaultMountPath
	}
	for _, vol := range pod.Spec.Volumes {
		if vol.CSI != nil && vol.CSI.Driver == csiDriverName && vol.CSI.VolumeAttributes["secretProviderClass"] == spc {
			return false, nil
		}
	}
	volume := corev1.Volume{
		Name: defaultVolumeName,
		VolumeSource: corev1.VolumeSource{
			CSI: &corev1.CSIVolumeSource{
				Driver:   csiDriverName,
				ReadOnly: boolPtr(true),
				VolumeAttributes: map[string]string{
					"secretProviderClass": spc,
				},
			},
		},
	}
	pod.Spec.Volumes = append(pod.Spec.Volumes, volume)
	for i := range pod.Spec.Containers {
		pod.Spec.Containers[i].VolumeMounts = append(pod.Spec.Containers[i].VolumeMounts, corev1.VolumeMount{
			Name:      defaultVolumeName,
			MountPath: mountPath,
			ReadOnly:  true,
		})
	}
	return true, nil
}

// BuildJSONPatch returns a JSON Patch for the pod mutation.
func BuildJSONPatch(pod *corev1.Pod) ([]byte, error) {
	changed, err := MutatePod(pod)
	if err != nil || !changed {
		return nil, err
	}
	ops := []map[string]any{
		{
			"op":    "add",
			"path":  "/spec/volumes/-",
			"value": pod.Spec.Volumes[len(pod.Spec.Volumes)-1],
		},
	}
	for i, c := range pod.Spec.Containers {
		mount := c.VolumeMounts[len(c.VolumeMounts)-1]
		ops = append(ops, map[string]any{
			"op":    "add",
			"path":  fmt.Sprintf("/spec/containers/%d/volumeMounts/-", i),
			"value": mount,
		})
	}
	return json.Marshal(ops)
}

// HandleAdmissionReview patches Pod create/update requests.
func HandleAdmissionReview(review admissionv1.AdmissionReview) admissionv1.AdmissionReview {
	resp := admissionv1.AdmissionResponse{
		UID:     review.Request.UID,
		Allowed: true,
	}
	if review.Request == nil {
		resp.Allowed = false
		resp.Result = &metav1.Status{Message: "missing admission request"}
		review.Response = &resp
		return review
	}
	if review.Request.Kind.Kind != "Pod" {
		review.Response = &resp
		return review
	}
	var pod corev1.Pod
	if err := json.Unmarshal(review.Request.Object.Raw, &pod); err != nil {
		resp.Allowed = false
		resp.Result = &metav1.Status{Message: fmt.Sprintf("decode pod: %v", err)}
		review.Response = &resp
		return review
	}
	patch, err := BuildJSONPatch(&pod)
	if err != nil {
		resp.Allowed = false
		resp.Result = &metav1.Status{Message: err.Error()}
		review.Response = &resp
		return review
	}
	if patch == nil {
		review.Response = &resp
		return review
	}
	patchType := admissionv1.PatchTypeJSONPatch
	resp.Patch = patch
	resp.PatchType = &patchType
	review.Response = &resp
	return review
}

func boolPtr(v bool) *bool { return &v }

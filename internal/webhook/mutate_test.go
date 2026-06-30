package webhook_test

import (
	"encoding/json"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/kubenexis/knxvault/internal/webhook"
)

func TestMutatePodAddsCSIVolume(t *testing.T) {
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				"knxvault.io/inject":                "true",
				"knxvault.io/secret-provider-class": "app-db",
				"knxvault.io/inject-mount-path":     "/mnt/secrets",
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "app", Image: "busybox"}},
		},
	}
	changed, err := webhook.MutatePod(&pod)
	if err != nil || !changed {
		t.Fatalf("MutatePod() changed=%v err=%v", changed, err)
	}
	if len(pod.Spec.Volumes) != 1 || pod.Spec.Containers[0].VolumeMounts[0].MountPath != "/mnt/secrets" {
		t.Fatalf("unexpected pod spec: %+v", pod.Spec)
	}
}

func TestHandleAdmissionReview(t *testing.T) {
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				"knxvault.io/inject":                "true",
				"knxvault.io/secret-provider-class": "app-db",
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "app", Image: "busybox"}},
		},
	}
	raw, err := json.Marshal(pod)
	if err != nil {
		t.Fatal(err)
	}
	review := admissionv1.AdmissionReview{
		Request: &admissionv1.AdmissionRequest{
			UID:    "uid-1",
			Kind:   metav1.GroupVersionKind{Kind: "Pod"},
			Object: runtime.RawExtension{Raw: raw},
		},
	}
	out := webhook.HandleAdmissionReview(review)
	if out.Response == nil || !out.Response.Allowed || len(out.Response.Patch) == 0 {
		t.Fatalf("unexpected response: %+v", out.Response)
	}
}

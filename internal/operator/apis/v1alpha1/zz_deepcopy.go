package v1alpha1

import (
	"k8s.io/apimachinery/pkg/runtime"
)

func (in *KNXVaultCA) DeepCopyInto(out *KNXVaultCA) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	out.Spec = in.Spec
	if in.Spec.ParentRef != nil {
		p := *in.Spec.ParentRef
		out.Spec.ParentRef = &p
	}
	out.Status = in.Status
	if in.Status.Conditions != nil {
		out.Status.Conditions = append([]Condition(nil), in.Status.Conditions...)
	}
}

func (in *KNXVaultCA) DeepCopy() *KNXVaultCA {
	if in == nil {
		return nil
	}
	out := new(KNXVaultCA)
	in.DeepCopyInto(out)
	return out
}

func (in *KNXVaultCA) DeepCopyObject() runtime.Object { return in.DeepCopy() }

func (in *KNXVaultCAList) DeepCopyInto(out *KNXVaultCAList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		out.Items = make([]KNXVaultCA, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&out.Items[i])
		}
	}
}

func (in *KNXVaultCAList) DeepCopy() *KNXVaultCAList {
	if in == nil {
		return nil
	}
	out := new(KNXVaultCAList)
	in.DeepCopyInto(out)
	return out
}

func (in *KNXVaultCAList) DeepCopyObject() runtime.Object { return in.DeepCopy() }

func (in *KNXVaultIssuer) DeepCopyInto(out *KNXVaultIssuer) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	out.Spec = in.Spec
	if in.Spec.CARef != nil {
		p := *in.Spec.CARef
		out.Spec.CARef = &p
	}
	out.Status = in.Status
	if in.Status.Conditions != nil {
		out.Status.Conditions = append([]Condition(nil), in.Status.Conditions...)
	}
}

func (in *KNXVaultIssuer) DeepCopy() *KNXVaultIssuer {
	if in == nil {
		return nil
	}
	out := new(KNXVaultIssuer)
	in.DeepCopyInto(out)
	return out
}

func (in *KNXVaultIssuer) DeepCopyObject() runtime.Object { return in.DeepCopy() }

func (in *KNXVaultIssuerList) DeepCopyInto(out *KNXVaultIssuerList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		out.Items = make([]KNXVaultIssuer, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&out.Items[i])
		}
	}
}

func (in *KNXVaultIssuerList) DeepCopy() *KNXVaultIssuerList {
	if in == nil {
		return nil
	}
	out := new(KNXVaultIssuerList)
	in.DeepCopyInto(out)
	return out
}

func (in *KNXVaultIssuerList) DeepCopyObject() runtime.Object { return in.DeepCopy() }

func (in *KNXVaultClusterIssuer) DeepCopyInto(out *KNXVaultClusterIssuer) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	out.Spec = in.Spec
	if in.Spec.CARef != nil {
		p := *in.Spec.CARef
		out.Spec.CARef = &p
	}
	out.Status = in.Status
	if in.Status.Conditions != nil {
		out.Status.Conditions = append([]Condition(nil), in.Status.Conditions...)
	}
}

func (in *KNXVaultClusterIssuer) DeepCopy() *KNXVaultClusterIssuer {
	if in == nil {
		return nil
	}
	out := new(KNXVaultClusterIssuer)
	in.DeepCopyInto(out)
	return out
}

func (in *KNXVaultClusterIssuer) DeepCopyObject() runtime.Object { return in.DeepCopy() }

func (in *KNXVaultClusterIssuerList) DeepCopyInto(out *KNXVaultClusterIssuerList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		out.Items = make([]KNXVaultClusterIssuer, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&out.Items[i])
		}
	}
}

func (in *KNXVaultClusterIssuerList) DeepCopy() *KNXVaultClusterIssuerList {
	if in == nil {
		return nil
	}
	out := new(KNXVaultClusterIssuerList)
	in.DeepCopyInto(out)
	return out
}

func (in *KNXVaultClusterIssuerList) DeepCopyObject() runtime.Object { return in.DeepCopy() }

func (in *KNXVaultCertificate) DeepCopyInto(out *KNXVaultCertificate) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	out.Spec = in.Spec
	if in.Spec.DNSNames != nil {
		out.Spec.DNSNames = append([]string(nil), in.Spec.DNSNames...)
	}
	if in.Spec.IPAddresses != nil {
		out.Spec.IPAddresses = append([]string(nil), in.Spec.IPAddresses...)
	}
	if in.Spec.Usages != nil {
		out.Spec.Usages = append([]string(nil), in.Spec.Usages...)
	}
	out.Status = in.Status
	if in.Status.Conditions != nil {
		out.Status.Conditions = append([]Condition(nil), in.Status.Conditions...)
	}
}

func (in *KNXVaultCertificate) DeepCopy() *KNXVaultCertificate {
	if in == nil {
		return nil
	}
	out := new(KNXVaultCertificate)
	in.DeepCopyInto(out)
	return out
}

func (in *KNXVaultCertificate) DeepCopyObject() runtime.Object { return in.DeepCopy() }

func (in *KNXVaultCertificateList) DeepCopyInto(out *KNXVaultCertificateList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		out.Items = make([]KNXVaultCertificate, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&out.Items[i])
		}
	}
}

func (in *KNXVaultCertificateList) DeepCopy() *KNXVaultCertificateList {
	if in == nil {
		return nil
	}
	out := new(KNXVaultCertificateList)
	in.DeepCopyInto(out)
	return out
}

func (in *KNXVaultCertificateList) DeepCopyObject() runtime.Object { return in.DeepCopy() }

func (in *KNXVaultCertificateRequest) DeepCopyInto(out *KNXVaultCertificateRequest) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	out.Spec = in.Spec
	if in.Spec.DNSNames != nil {
		out.Spec.DNSNames = append([]string(nil), in.Spec.DNSNames...)
	}
	if in.Spec.Usages != nil {
		out.Spec.Usages = append([]string(nil), in.Spec.Usages...)
	}
	out.Status = in.Status
	if in.Status.Conditions != nil {
		out.Status.Conditions = append([]Condition(nil), in.Status.Conditions...)
	}
}

func (in *KNXVaultCertificateRequest) DeepCopy() *KNXVaultCertificateRequest {
	if in == nil {
		return nil
	}
	out := new(KNXVaultCertificateRequest)
	in.DeepCopyInto(out)
	return out
}

func (in *KNXVaultCertificateRequest) DeepCopyObject() runtime.Object { return in.DeepCopy() }

func (in *KNXVaultCertificateRequestList) DeepCopyInto(out *KNXVaultCertificateRequestList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		out.Items = make([]KNXVaultCertificateRequest, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&out.Items[i])
		}
	}
}

func (in *KNXVaultCertificateRequestList) DeepCopy() *KNXVaultCertificateRequestList {
	if in == nil {
		return nil
	}
	out := new(KNXVaultCertificateRequestList)
	in.DeepCopyInto(out)
	return out
}

func (in *KNXVaultCertificateRequestList) DeepCopyObject() runtime.Object {
	return in.DeepCopy()
}

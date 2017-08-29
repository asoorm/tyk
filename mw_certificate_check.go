package main

import "net/http"

type CertificateCheckMW struct {
	*BaseMiddleware
}

func (m *CertificateCheckMW) Name() string {
	return "CertificateCheckMW"
}

func (m *CertificateCheckMW) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {
	if m.Spec.UseMutualTLSAuth {
		if err := validateRequestCertificate(m.Spec.ClientCertificates, r); err != nil {
			return err, 403
		}
	}
	return nil, 200
}

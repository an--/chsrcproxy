package protocol

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
)

type Keystore struct {
	CACert      *x509.Certificate
	LocalPriKey *rsa.PrivateKey
	LocalCert   *x509.Certificate

	RootCertPool *x509.CertPool
}

var localKeyStore Keystore

func InitKeystore(caCertB, priKeyB, localCertB *pem.Block) error {
	var caCert, caPErr = x509.ParseCertificate(caCertB.Bytes)
	if nil != caPErr {
		return caPErr
	}

	var priKey, priKErr = x509.ParsePKCS1PrivateKey(priKeyB.Bytes)
	if nil != priKErr {
		return priKErr
	}

	var localCert, servCErr = x509.ParseCertificate(localCertB.Bytes)
	if nil != servCErr {
		return servCErr
	}

	var rootCertPool = x509.NewCertPool()
	rootCertPool.AddCert(caCert)
	localKeyStore = Keystore{
		CACert:       caCert,
		LocalPriKey:  priKey,
		LocalCert:    localCert,
		RootCertPool: rootCertPool,
	}
	return nil
}

func GetLocalKeyStore() *Keystore {
	return &localKeyStore
}

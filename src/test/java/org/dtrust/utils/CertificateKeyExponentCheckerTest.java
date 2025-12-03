package org.dtrust.utils;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;

import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.dtrust.util.CertificateKeyExponentChecker;
import org.junit.Test;

public class CertificateKeyExponentCheckerTest {
	
	@Test
	public void testValidExponent_assertTrue() throws Exception {
		
		InputStream certStream = this.getClass().getClassLoader().getResourceAsStream("certs/crlSignCert.der");
		
		X509Certificate testCert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(certStream);
		
		assertTrue(CertificateKeyExponentChecker.isPublicKeyExponentValid(testCert));
		
	}
	
	@Test
	public void testInvalidExponent_assertFalse() throws Exception {
		
		InputStream certStream = this.getClass().getClassLoader().getResourceAsStream("certs/MaxmdCAv4.0.der");
		
		X509Certificate testCert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(certStream);
		
		assertFalse(CertificateKeyExponentChecker.isPublicKeyExponentValid(testCert));
		
	}

}

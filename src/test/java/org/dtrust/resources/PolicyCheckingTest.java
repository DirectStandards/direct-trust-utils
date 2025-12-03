package org.dtrust.resources;

import static org.junit.Assert.assertTrue;

import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.junit.Test;
import org.nhindirect.policy.PolicyExpression;
import org.nhindirect.policy.PolicyFilter;
import org.nhindirect.policy.PolicyFilterFactory;
import org.nhindirect.policy.PolicyLexicon;
import org.nhindirect.policy.PolicyLexiconParser;
import org.nhindirect.policy.PolicyLexiconParserFactory;

public class PolicyCheckingTest {

	@Test
	public void testPolicyOIDRegEx() throws Exception {
		
		InputStream ioStream = this.getClass().getClassLoader().getResourceAsStream("policies/interopTestCertPolicy.pol");
		final PolicyLexiconParser parser = PolicyLexiconParserFactory.getInstance(PolicyLexicon.SIMPLE_TEXT_V1);
		PolicyExpression certPolicy = parser.parse(ioStream);
		
		final PolicyFilter filter = PolicyFilterFactory.getInstance();
		
		InputStream certStream = this.getClass().getClassLoader().getResourceAsStream("certs/hdavis@unionhealth.cernerdirect.co(1).der");
		
		X509Certificate testCert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(certStream);
		
		assertTrue(filter.isCompliant(testCert, certPolicy));
		
	}
	
	@Test
	public void testPolicyOIDRegEx_coveredEnitytCertPolicyOID() throws Exception {
		
		InputStream ioStream = this.getClass().getClassLoader().getResourceAsStream("policies/interopTestCertPolicy.pol");
		final PolicyLexiconParser parser = PolicyLexiconParserFactory.getInstance(PolicyLexicon.SIMPLE_TEXT_V1);
		PolicyExpression certPolicy = parser.parse(ioStream);
		
		final PolicyFilter filter = PolicyFilterFactory.getInstance();
		
		InputStream certStream = this.getClass().getClassLoader().getResourceAsStream("certs/hospitalmenonitaguayama@mghpr.direct.securehit.net.der");
		
		X509Certificate testCert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(certStream);
		
		assertTrue(filter.isCompliant(testCert, certPolicy));
		
	}
	
}

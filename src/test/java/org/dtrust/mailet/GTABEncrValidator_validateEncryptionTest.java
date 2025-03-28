package org.dtrust.mailet;

import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.Matchers.eq;

import java.io.File;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;

import javax.mail.internet.InternetAddress;

import org.apache.commons.io.FileUtils;
import org.junit.Test;
import org.nhindirect.stagent.NHINDAddress;
import org.nhindirect.stagent.NHINDAddressCollection;
import org.nhindirect.stagent.cert.CertificateStore;
import org.nhindirect.stagent.mail.Message;

public class GTABEncrValidator_validateEncryptionTest 
{
	@Test
	public void testValidateKeyUsage() throws Exception
	{
		GTABValidationReportAttr report = new GTABValidationReportAttr();
		
		final Message msg = new Message(FileUtils.openInputStream(new File("./src/test/resources/messages/ValidKeyUsage.txt")));
		
		final X509Certificate keyEncCert = (X509Certificate)CertificateFactory.getInstance("X.509").
				generateCertificate(FileUtils.openInputStream(new File("./src/test/resources/certs/operations.cernerdirect.com-keyEnc.der")));
		
		final Collection<X509Certificate> retCerts = Arrays.asList(keyEncCert);
		

		
		final CertificateStore store = mock(CertificateStore.class);
		final InternetAddress addr = new InternetAddress("operations.cernerdirect.com");
		when(store.getCertificates(eq(addr))).thenReturn(retCerts);
		
		NHINDAddressCollection recips = new NHINDAddressCollection();
		recips.add(new NHINDAddress("gm2552@operations.cernerdirect.com"));
		
		EncrValidator.setCertificateStore(store);
		try
		{
			report = EncrValidator.validateEncryption(msg, report, recips, null, true);
			GTABValidationReportAttr.DigSigReport digSigReport = new GTABValidationReportAttr.DigSigReport();
			digSigReport.encouteredOID = "2.16.840.1.101.3.4.2.1";
			report.digSigReport = digSigReport;
			report.encrReport.keyEncryptionOID = "1.2.840.113549.1.1.7";
			report.encrReport.keyEncryptionMaskGenerationAlgorithmOID = "1.2.840.113549.1.1.8";
			report.encrReport.keyEncryptionDigestOID = "1.3.14.3.2.26";
			String s = report.toString();
			String encAlg = GTABValidationReportAttr.getEncryptionAlgorithmFromOID("2.16.840.1.101.3.4.1.2");


			assertTrue(report.encrReport.encrValid);
		}
		finally
		{
			EncrValidator.setCertificateStore(null);
		}
	}
}

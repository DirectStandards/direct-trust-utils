package org.dtrust.mailet;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;
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
    private GTABValidationReportAttr doValidation(String messageFile, boolean ignoreOAEPCompliance) throws Exception {
        GTABValidationReportAttr report = new GTABValidationReportAttr();

        final Message msg = new Message(FileUtils.openInputStream(new File(messageFile)));

        final X509Certificate keyEncCert = (X509Certificate)CertificateFactory.getInstance("X.509").
                generateCertificate(FileUtils.openInputStream(new File("./src/test/resources/certs/operations.cernerdirect.com-keyEnc.der")));

        final Collection<X509Certificate> retCerts = Arrays.asList(keyEncCert);

        final CertificateStore store = mock(CertificateStore.class);
        final InternetAddress addr = new InternetAddress("gm2552@operations.cernerdirect.com");
        when(store.getCertificates(eq(addr))).thenReturn(retCerts);

        NHINDAddressCollection recips = new NHINDAddressCollection();
        recips.add(new NHINDAddress("gm2552@operations.cernerdirect.com"));

        EncrValidator.setCertificateStore(store);
        try
        {
            return EncrValidator.validateEncryption(msg, report, recips, null, true, ignoreOAEPCompliance);
        }
        finally
        {
            EncrValidator.setCertificateStore(null);
        }
    }

	@Test
	public void testValidateKeyUsage() throws Exception
	{
		GTABValidationReportAttr report = doValidation("./src/test/resources/messages/ValidKeyUsage.txt", true);

        assertTrue(report.encrReport.encrValid);
        assertEquals("1.2.840.113549.1.1.1", report.encrReport.keyEncryptionOID);

	}

    @Test
    public void testNonAOEPUsageEncryption_ignoreOAEPCompliance_assertValid() throws Exception
    {
        GTABValidationReportAttr report = doValidation("./src/test/resources/messages/ValidKeyUsage.txt", true);

        assertTrue(report.encrReport.encrValid);
        assertEquals("1.2.840.113549.1.1.1", report.encrReport.keyEncryptionOID);
    }

    @Test
    public void testNonAOEPUsageEncryption_enforceOAEPCompliance_assertNonValid() throws Exception
    {
        GTABValidationReportAttr report = doValidation("./src/test/resources/messages/ValidKeyUsage.txt", false);
        assertFalse(report.encrReport.encrValid);
    }
}

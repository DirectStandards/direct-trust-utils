package org.dtrust.resources;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.File;
import java.io.InputStream;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;

import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyLong;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.dtrust.dao.interoptest.dao.TestSuiteDAO;
import org.dtrust.dao.interoptest.entity.TestSuite;
import org.dtrust.dao.interoptest.entity.TestType;
import org.dtrust.resources.utils.MessageBuilderUtils;
import org.dtrust.resources.utils.PrivateCertResolver;
import org.dtrust.util.MessageSender;
import org.dtrust.util.SMTPMessageSender;
import org.junit.Before;
import org.junit.Test;
import org.nhindirect.stagent.cert.CertificateResolver;
import org.nhindirect.gateway.smtp.config.cert.impl.CertStoreUtils;
import org.nhindirect.stagent.cert.impl.DNSCertificateStore;
import org.nhindirect.stagent.cryptography.DigestAlgorithm;
import org.nhindirect.stagent.cryptography.EncryptionAlgorithm;
import org.nhindirect.stagent.cryptography.SMIMECryptographerImpl;

public class TestSendMessageTest
{
	protected InteropTestResource rec;
	protected CertificateResolver privResolver;
	protected MessageSender msgSender;
	
	@Before
	public void setUp() throws Exception
	{
		rec = new InteropTestResource();
		rec.setLocalDomain("direct.securehealthemail.com");
		rec.setLocalSender("atabInterop@direct.securehealthemail.com");
		
		final InputStream ioStream = FileUtils.openInputStream(new File("./src/test/resources/certs/direct.securehealthemail.com-digSig.p12"));
		final X509Certificate cert = CertStoreUtils.certFromData(null, IOUtils.toByteArray(ioStream));
		IOUtils.closeQuietly(ioStream);
		
		privResolver = mock(CertificateResolver.class);
		when(privResolver.getCertificates((InternetAddress)any())).thenReturn(Arrays.asList(cert));
		
		rec.setPrivateCertResolver(privResolver);
		
		msgSender = mock(MessageSender.class);

		//msgSender = new SMTPMessageSender("25", "securehealthemail.com", "gm2552", "1kingpuff");
		
		rec.setMsgSender(msgSender);
		
		TestSuiteDAO dao = mock(TestSuiteDAO.class);
		when(dao.initiateTestSuite((String)any(), (String)any(), anyInt())).thenReturn(new TestSuite());
		when(dao.initiateTest((String)any(), (TestType)any(), anyLong())).thenReturn(new org.dtrust.dao.interoptest.entity.Test());

		rec.setDao(dao);
		
	}
	
	@Test
	public void testSendMessage() throws Exception
	{
		//rec.testSendMessage("gm2552@direct.securehealthemail.com");
		rec.testSendMessage(null, "gm2552@demo.sandboxcernerdirect.com", 2);
	}

	@Test
	public void testSendRevokedMessage() throws Exception
	{
		InteropTestResource interopTestResource = new InteropTestResource();
		interopTestResource.setLocalDomain("direct2.directtrust.org");
		interopTestResource.setLocalSender("atabInterop@direct2.directtrust.org");
		InternetAddress to = new InternetAddress("eric@direct.javari.directtrust.org");

		Collection<CertificateResolver> publicCertResolvers;
		publicCertResolvers = new ArrayList<CertificateResolver>();
		publicCertResolvers.add(new DNSCertificateStore(Arrays.asList("8.8.8.8")));

		PrivateCertResolver privateCertResolver = new PrivateCertResolver();
		privateCertResolver.setGoodCertificateFile("certs/good.p12");
		privateCertResolver.setExpiredCertificateFile("certs/expired.p12");
		privateCertResolver.setNonTrustedCertificateFile("certs/nonTrusted.p12");
		privateCertResolver.setRevokedCertificateFile("certs/revoked.p12");

		MimeMessage  exceptionPathMessage = MessageBuilderUtils.createMimeMessage(Arrays.asList(to), new InternetAddress("atabInterop@direct2.directtrust.org"), "Exception path, revoked cert", ""
				+ "This is a test message using a revoked certificate.", null , null, null, false);

		SMIMECryptographerImpl crypto = new SMIMECryptographerImpl(EncryptionAlgorithm.AES128, DigestAlgorithm.SHA256WITHRSA , EncryptionAlgorithm.RSA_PKCS1_V15, null);

		MimeMessage staEncryptedMsg = MessageBuilderUtils.createDirectMessage(publicCertResolvers, privateCertResolver, crypto,
				exceptionPathMessage, Arrays.asList(PrivateCertResolver.REVOKED));

		SMTPMessageSender smtpMessageSender = new SMTPMessageSender("25", "direct.javari.directtrust.org", "gm2552", "1kingpuff");
		smtpMessageSender.sendMessage(staEncryptedMsg);


	}
}

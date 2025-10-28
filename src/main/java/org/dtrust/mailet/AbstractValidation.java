package org.dtrust.mailet;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;

import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.Message.RecipientType;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.mailet.Mail;
//import org.nhind.config.ConfigurationServiceProxy;
import org.nhind.config.rest.CertificateService;
import org.nhind.config.rest.feign.CertificateClient;
import org.nhindirect.common.mail.SMTPMailMessage;
import org.nhindirect.common.rest.exceptions.ServiceException;
import org.nhindirect.config.model.Certificate;
import org.nhindirect.gateway.smtp.dsn.DSNCreator;
import org.nhindirect.gateway.smtp.james.mailet.AbstractNotificationAwareMailet;
import org.nhindirect.gateway.util.MessageUtils;
import org.nhindirect.stagent.NHINDAddress;
import org.nhindirect.stagent.NHINDAddressCollection;
import org.nhindirect.stagent.cert.X509CertificateEx;
import org.nhindirect.stagent.cryptography.SMIMECryptographerImpl;
import org.nhindirect.stagent.mail.Message;
import org.nhindirect.stagent.mail.MimeEntity;

import com.google.inject.Provider;
import org.springframework.context.ApplicationContext;

import static org.nhindirect.gateway.util.MessageUtils.getSender;


public abstract class AbstractValidation extends AbstractNotificationAwareMailet
{


	private static final Log LOGGER = LogFactory.getFactory().getInstance(GTABValidation.class);	

	protected static final String TEST_REG_BASE_URL = "TestRegServiceURL";
	protected static final String TEST_REG_USERNAME = "TestRegUserName";
	protected static final String TEST_REG_PASSWORD = "TestRegPassword";
	
	protected static final String DEFAULT_REPORT_RECIP = "gm2552@cerner.com";
	
	protected final static String REPORT_RECIP_PARAMS = "ValidationReportRecips";
	
	protected final static String REPORT_SENDER_PARAMS = "ValidationReportSender";

    protected final static String IGNORE_NON_COMPLIANT_OAEP_ENCRYPTION = "IgnoreNonCompliantOAEPEncryption";

	protected Collection<InternetAddress> reportRecips;
	
	protected InternetAddress reportSender;

    // Flag to toggle on and off enforcement of the OAEP encryption requirements which
    // go into effect Jan 1 2026.
    protected boolean ignoreNonCompliantOAEPEncryption;
	
	//protected ConfigurationServiceProxy proxy;
	protected CertificateService certificateService;
	protected ApplicationContext ctx;

	@Override
	public void init() throws MessagingException
	{
		super.init();

		// Get the configuration URL
		final String configURLParam = getInitParameter("ConfigURL");
		if (StringUtils.isEmpty(configURLParam))
		{
			LOGGER.error("GTABValidation Configuration URL cannot be empty or null.");
			throw new MessagingException("GTABValidation Configuration URL cannot be empty or null.");
		}	
		
		
		if (StringUtils.isEmpty(configURLParam))
		{
			LOGGER.error("Configuration URL cannot be empty or null.");
			throw new MessagingException("Configuration Configuration URL cannot be empty or null.");
		}


		// create an instance of the Config Service for getting private keys
		//proxy = new ConfigurationServiceProxy(configURLParam);


		// get the report sender 
		final String senderParamValue = getMailetConfig().getInitParameter(REPORT_SENDER_PARAMS);
		if (StringUtils.isEmpty(senderParamValue))
		{
			LOGGER.error("Report sender address cannot be empty or null.");
			throw new MessagingException("Report sender address cannot be empty or null.");
		}
		
		reportSender = new InternetAddress(senderParamValue);
		
		// get the report recipients
		reportRecips = new ArrayList<InternetAddress>();
		
		final String recipParamValue = getMailetConfig().getInitParameter(REPORT_RECIP_PARAMS);
		if (StringUtils.isEmpty(recipParamValue))
		{
			LOGGER.info("Validation report recipient parameter is not set.  Defaulting to " + DEFAULT_REPORT_RECIP);
			reportRecips.add(new InternetAddress(DEFAULT_REPORT_RECIP));
		}
		else
		{
			// comma delimited
			final String[] recipAddresses = recipParamValue.split(",");
			for (String recipAddr : recipAddresses)
				reportRecips.add(new InternetAddress(recipAddr));
		}

        // get the configuration for OAEP Encryption enforcement.  Default to true if not set
        // for backward behavioural passivity.
        final String ignoreOAEPParamValue = getMailetConfig().getInitParameter(IGNORE_NON_COMPLIANT_OAEP_ENCRYPTION);
        if (StringUtils.isEmpty(ignoreOAEPParamValue))
        {
            LOGGER.info("Ignore OAEP enforcement parameter is not set.  Defaulting to true (will ignore enforcement)");
            ignoreNonCompliantOAEPEncryption = true;
        }
        else
            ignoreNonCompliantOAEPEncryption = Boolean.valueOf(ignoreOAEPParamValue);
	}
	/**
	 * Creates a spring application context.
	 * @return Spring application context.
	 */
	protected ApplicationContext createSpringApplicationContext()
	{
		return null;
	}


	@Override
	public void service(Mail mail) throws MessagingException 
	{	
		LOGGER.info("Received message for validation.");
		
		// get the message		
		final Message msg = new Message(mail.getMessage());
		
		// get the recipient list
		//final NHINDAddressCollection recips = this.getMailRecipients(mail);
		final SMTPMailMessage smtpMailMessage = mailToSMTPMailMessage(mail);
		final NHINDAddressCollection recips = MessageUtils.getMailRecipients(smtpMailMessage);
		
		final ValidationReportAttr report = validateMessageAttributes(msg, recips);
		
		// create a report message and send it to the report recips
		final MimeMessage reportMsg = new MimeMessage((Session)null);
		
		final InternetAddress sendAddr = getSender(smtpMailMessage);
		//final InternetAddress sendAddr = getSender(mail);

		report.fromAddr = sendAddr.toString();
		for (NHINDAddress toAddr : recips)
		{
			report.toAddrs.add(toAddr.toString());
		}
		report.messageId = msg.getMessageID();
		
		reportMsg.setSubject(getReportSubject() + " " + sendAddr.toString());
		reportMsg.setFrom(reportSender);

		Collection<InternetAddress> reportAddresses = new ArrayList<InternetAddress>();
		reportAddresses.addAll(reportRecips);

		final Collection<InternetAddress> additionalAddresses = this.getAdditionalReportAddrs(sendAddr.getAddress());
		if (additionalAddresses != null) {
			reportAddresses.addAll(additionalAddresses);
		}
		reportMsg.addRecipients(RecipientType.TO, reportAddresses.toArray(new InternetAddress[reportAddresses.size()]));

		reportMsg.setText(report.toString());
		
		reportMsg.saveChanges();
		
		// use the mailet capability and put this message on the queue
		getMailetContext().sendMail(reportMsg);
		
		LOGGER.info("Sending validation report to " + reportMsg.getHeader("To", ",") + " from " + reportSender.getAddress());
		// emm I think if we uncomment below it shouldn't continue on the mailet container chain?
		mail.setState(Mail.GHOST);
	}
	
	protected MimeEntity decryptMessage(Message msg, NHINDAddressCollection recips) throws Exception
	{
		// decrypt the message
		
		// first get the certificates needed to decrypt the message
		final Collection<X509Certificate> lookupCerts = EncrValidator.getRecipCerts(recips, certificateService);
		//final Collection<X509Certificate> lookupCerts = EncrValidator.getRecipCerts(recips, proxy);
		final Collection<X509CertificateEx> decryptCerts = new ArrayList<X509CertificateEx>();
		for (X509Certificate lookupCert : lookupCerts)
		{
			if (lookupCert instanceof X509CertificateEx)
				decryptCerts.add((X509CertificateEx)lookupCert);
		}
		
		final SMIMECryptographerImpl crypto = new SMIMECryptographerImpl();
		
		return crypto.decrypt(msg.extractMimeEntity(), decryptCerts);
	}
	
	//@Override
	protected Provider<DSNCreator> getDSNProvider() 
	{
		return null;
	}
	
	protected abstract ValidationReportAttr validateMessageAttributes(Message msg, NHINDAddressCollection recips);
	
	protected abstract String getReportSubject();
	
	protected abstract Collection<InternetAddress> getAdditionalReportAddrs(String sourceAddr);
}

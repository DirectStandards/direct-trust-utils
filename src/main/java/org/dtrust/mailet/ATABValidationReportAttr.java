package org.dtrust.mailet;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.operator.DefaultAlgorithmNameFinder;

public class ATABValidationReportAttr extends GTABValidationReportAttr
{

	public ATABValidationReportAttr()
	{
		super();
	}
	
	@Override
	public String toString()
	{
		final StringBuilder builder = new StringBuilder();
		
		builder.append("Bundle Testing Tool Message Send Test Validation Report:\r\n\r\n");
		
		builder.append("From: " + fromAddr + "\r\n");
		builder.append("Recipients:\r\n");
		for (String recip : toAddrs)
		{
			builder.append("\t" + recip + "\r\n");
		}
		builder.append("Message Id: " + messageId + "\r\n\r\n");
		
		builder.append("Encryption Validation:\r\n");
		if (encrReport != null)
		{

			builder.append("\tEncryption Validation Status: " + encrReport.encrValid + "\r\n");
			//builder.append("\tEncryption Algorithm OID: " + encrReport.encouteredOID +  "(" +  getEncryptionAlgorithmFromOID(encrReport.encouteredOID) + ")\r\n");
			builder.append("\tEncryption Algorithm OID: " + encrReport.encouteredOID +  "(" +  customAlgorithmFinder(new ASN1ObjectIdentifier(encrReport.encouteredOID.toString())) + ")\r\n");
			builder.append("\tKey Encryption Algorithm OID: " + encrReport.keyEncryptionOID + "(" +  customAlgorithmFinder(new ASN1ObjectIdentifier(encrReport.keyEncryptionOID)) + ")\r\n");
			if( encrReport.keyEncryptionDigestOID != null) {
				//builder.append("\tKey Encryption Digest: " + encrReport.keyEncryptionDigestOID + "(" + getKeyEncryptionDigest(encrReport.keyEncryptionDigestOID) + ")\r\n");
				builder.append("\tKey Encryption Digest: " + encrReport.keyEncryptionDigestOID + "(" + customAlgorithmFinder(new ASN1ObjectIdentifier(encrReport.keyEncryptionDigestOID)) + ")\r\n");
			}
			if( encrReport.keyEncryptionMaskGenerationAlgorithmOID != null) {
				builder.append("\tKey Encryption Mask Generation Algorithm: " + encrReport.keyEncryptionMaskGenerationAlgorithmOID + "(" + getMaskFunctionGeneratorFromOID(encrReport.keyEncryptionMaskGenerationAlgorithmOID) + ")\r\n");
			}
			builder.append("\tComments: " + encrReport.comment + "\r\n\r\n");
		}
		else
		{
			builder.append("\tN/A\r\n\r\n");
		}
		
		builder.append("Digital Signature Validation:\r\n");
		if (digSigReport != null)
		{
			builder.append("\tDigital Signature Validation Status: " + digSigReport.digSigValid + "\r\n");
			builder.append("\tDigest Algorithm OID: " + digSigReport.encouteredOID + " (" + getKeyEncryptionDigest(digSigReport.encouteredOID) + ")\r\n");
			builder.append("\tComments: " + digSigReport.comment + "\r\n\r\n");
		}
		else
		{
			builder.append("\tN/A\r\n\r\n");
		}
		
		
		builder.append("Message Wrapping Validation:\r\n");
		if (wrappedReport != null)
		{
			builder.append("\tMessage Wrapping Validation Status: " + wrappedReport.isWrapped + "\r\n\r\n");
		}
		else
		{
			builder.append("\tN/A\r\n\r\n");
		}
		
		builder.append("Final Validation Status: ");
		
		if (wrappedReport != null && wrappedReport.isWrapped && digSigReport != null &&
				digSigReport.digSigValid && encrReport != null && encrReport.encrValid)
			builder.append("SUCCESS");
		else
			builder.append("FAILED");
		
		return builder.toString();
	}




}


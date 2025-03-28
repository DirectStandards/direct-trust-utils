package org.dtrust.mailet;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.operator.DefaultAlgorithmNameFinder;
import org.nhindirect.stagent.cryptography.EncryptionAlgorithm;

public class GTABValidationReportAttr extends ValidationReportAttr
{
	public EncryReport encrReport;
	public DigSigReport digSigReport;
	public WrappedReport wrappedReport;
	
	public GTABValidationReportAttr()
	{
		super();
		encrReport = null;
		digSigReport = null;
	}
	
	public static class EncryReport
	{
		
		public boolean encrValid;
		public String encouteredOID;
		public String keyEncryptionOID;
		public String keyEncryptionDigestOID;
		public String keyEncryptionMaskGenerationAlgorithmOID;
		public String comment;
		
		public EncryReport()
		{
			encrValid = false;
			encouteredOID = "";
			comment = "";
			keyEncryptionOID= null;
			keyEncryptionDigestOID = null;
			keyEncryptionMaskGenerationAlgorithmOID = null;
		}
	}
	
	public static class DigSigReport
	{
		
		public boolean digSigValid;
		public String encouteredOID;
		public String comment;
		
		public DigSigReport()
		{
			digSigValid = false;
			encouteredOID = "";
			comment = "";
		}
	}	
	
	public static class WrappedReport
	{
		
		public boolean isWrapped;
		
		public WrappedReport()
		{
			isWrapped = false;
		}
	}
	
	@Override
	public String toString()
	{
		final StringBuilder builder = new StringBuilder();
		
		builder.append("GTAB Message Send Validation Report:\r\n\r\n");
		
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
			DefaultAlgorithmNameFinder defaultAlgorithmNameFinder = new DefaultAlgorithmNameFinder();
			builder.append("\tEnryption Validation Status: " + encrReport.encrValid + "\r\n");
			//builder.append("\tEncryption Algorithm OID: " + encrReport.encouteredOID +  "(" +  getEncryptionAlgorithmFromOID(encrReport.encouteredOID) + ")\r\n");
			builder.append("\tEncryption Algorithm OID: " + encrReport.encouteredOID +  "(" +  defaultAlgorithmNameFinder.getAlgorithmName(new ASN1ObjectIdentifier(encrReport.encouteredOID.toString())) + ")\r\n");
			builder.append("\tKey Encryption Alorithm OID: " + encrReport.keyEncryptionOID + "(" +  defaultAlgorithmNameFinder.getAlgorithmName(new ASN1ObjectIdentifier(encrReport.keyEncryptionOID)) + ")\r\n");
			if( encrReport.keyEncryptionDigestOID != null) {
				//builder.append("\tKey Encryption Digest: " + encrReport.keyEncryptionDigestOID + "(" + getKeyEncryptionDigest(encrReport.keyEncryptionDigestOID) + ")\r\n");
				builder.append("\tKey Encryption Digest: " + encrReport.keyEncryptionDigestOID + "(" + defaultAlgorithmNameFinder.getAlgorithmName(new ASN1ObjectIdentifier(encrReport.keyEncryptionDigestOID)) + ")\r\n");
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
			builder.append("\tDigital Signature Validation Status: " + digSigReport.digSigValid + "\r\n");
			builder.append("\tDigest Alorithm OID: " + digSigReport.encouteredOID + " (" + getKeyEncryptionDigest(digSigReport.encouteredOID) + ")\r\n");
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

	public static String getKeyEncryptionAlgorithmFromOID(String oid){
		if( oid.equals(PKCSObjectIdentifiers.id_RSAES_OAEP.toString()))
			return "RSAOAEP";
		if( oid.equals(PKCSObjectIdentifiers.rsaEncryption.toString()))
			return "RSAES-PKCS1-v1_5";
		return "unknown key encryption algorithm";
	}

	public static String getEncryptionAlgorithmFromOID( String oid){
		if( oid.equals(EncryptionAlgorithm.AES128.getOID())){
			return EncryptionAlgorithm.AES128.getAlgName();
		}
		if( oid.equals(EncryptionAlgorithm.AES128.getOID())){
			return EncryptionAlgorithm.AES128.getAlgName();
		}
		return "Unknown encryption algorithm";
	}

	public static String getKeyEncryptionDigest(String digestOid){
		if( digestOid.equals(CMSSignedDataGenerator.DIGEST_SHA1.toString()))
			return "SHA-1";
		if( digestOid.equals(CMSSignedDataGenerator.DIGEST_SHA256.toString()))
			return "SHA-256";
		if( digestOid.equals(CMSSignedDataGenerator.DIGEST_SHA384.toString()))
			return "SHA-384";
		if( digestOid.equals(CMSSignedDataGenerator.DIGEST_SHA512.toString()))
			return "SHA-512";
		return "Unknown SHA value: " + digestOid;
	}

	public static String getMaskFunctionGeneratorFromOID(String mfgOID){
		if( mfgOID.equals(PKCSObjectIdentifiers.id_mgf1.getId()))
			return "MGF1";

		return "Unknown MFG: " + mfgOID;
	}
}

package org.dtrust.util;

import java.math.BigInteger;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;


public class CertificateKeyExponentChecker {
	
	
	public static boolean isPublicKeyExponentValid(X509Certificate certToCheck) {
		
		PublicKey pubKey = certToCheck.getPublicKey();
		
		if (pubKey instanceof RSAPublicKey) {
			
			// get the public exponent and make sure it is at a value of 65537 (0x10001) and an odd number 
            RSAPublicKey rsaKey = (RSAPublicKey) pubKey;
            BigInteger exponent = rsaKey.getPublicExponent();
            
            // Define the minimum allowed value (65537)
            BigInteger minExponent = BigInteger.valueOf(65537);
            
            return (exponent.testBit(0) && exponent.compareTo(minExponent) >= 0);
            	
		}
		
		return true;
	}

}

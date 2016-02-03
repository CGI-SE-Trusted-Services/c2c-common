/************************************************************************
*                                                                       *
*  Certificate Service -  Car2Car Core                                  *
*                                                                       *
*  This software is free software; you can redistribute it and/or       *
*  modify it under the terms of the GNU Affero General Public License   *
*  License as published by the Free Software Foundation; either         *
*  version 3   of the License, or any later version.                    *
*                                                                       *
*  See terms of license at gnu.org.                                     *
*                                                                       *
*************************************************************************/
package org.certificateservices.custom.c2x.ieee1609dot2.generator;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;

import org.certificateservices.custom.c2x.common.crypto.AlgorithmIndicator;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.EccP256CurvePoint;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.EccP256CurvePoint.EccP256CurvePointChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.PublicVerificationKey.PublicVerificationKeyChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Signature;
import org.certificateservices.custom.c2x.ieee1609dot2.cert.Certificate;
import org.certificateservices.custom.c2x.ieee1609dot2.cert.CertificateType;
import org.certificateservices.custom.c2x.ieee1609dot2.cert.IssuerIdentifier;
import org.certificateservices.custom.c2x.ieee1609dot2.cert.ToBeSignedCertificate;
import org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager;


/**
 * Base CertGenerator class containing common methods.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */

public abstract class BaseCertGenerator {
	
	protected static final int DEFAULT_CERT_VERSION = 1;
	
	Ieee1609Dot2CryptoManager cryptoManager = null;
	boolean useUncompressed = false;
	
	
	public BaseCertGenerator(Ieee1609Dot2CryptoManager cryptoManager, boolean useUncompressed){
		this.cryptoManager = cryptoManager;
		this.useUncompressed = useUncompressed;
	}
	
	/**
	 * Generate and attaches a signature to the given certificate.
	 */
	protected Certificate signAndGenCertificate(int version, IssuerIdentifier issuerId, ToBeSignedCertificate tbs,  PublicVerificationKeyChoices alg, PrivateKey privateKey, CertificateType certType, Certificate signCert) throws IOException, IllegalArgumentException, SignatureException{
		Signature signature = cryptoManager.signMessage(tbs.getEncoded(), alg, privateKey, certType,signCert);
		
		return new Certificate(version, issuerId, tbs, signature);		
	}
	
	/**
	 * Help method to convert a public key to EccP256CurvePoint using given compression.
	 */
	EccP256CurvePoint convertToPoint(AlgorithmIndicator alg, PublicKey pk) throws IllegalArgumentException, InvalidKeySpecException{
		return cryptoManager.encodeEccPoint(alg, (useUncompressed ? EccP256CurvePointChoices.uncompressed : EccP256CurvePointChoices.compressedy0), pk);
	}
		
}

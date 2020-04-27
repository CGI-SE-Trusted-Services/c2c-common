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
import java.security.SignatureException;
import java.util.Map;

import org.certificateservices.custom.c2x.common.BadArgumentException;
import org.certificateservices.custom.c2x.common.CertStore;
import org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashAlgorithm;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId8;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature.SignatureChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.crl.basic.CrlContents;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.crl.secenv.CrlPsid;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.crl.secenv.SecuredCrl;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.HeaderInfo;


/**
 * Base SecuredCRLGenerator class containing classes to generated signed CRL files
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */

public class SecuredCrlGenerator extends SecuredDataGenerator{

	/**
	 * Main constructor.
	 * 
	 * @param version version if Ieee1609Dot2Data to generate.
	 * @param cryptoManager the related crypto manager
	 * @param hashAlgorithm the related hash algorithm used in messages
	 * @param signAlgorithm the related sign algorithm used in messages.
	 * @throws SignatureException if internal problems occurred initializing the generator.
	 */
	public SecuredCrlGenerator(int version,
			Ieee1609Dot2CryptoManager cryptoManager,
			HashAlgorithm hashAlgorithm, SignatureChoices signAlgorithm)
			throws SignatureException {
		super(version, cryptoManager, hashAlgorithm, signAlgorithm);
	}
	
	/**
	 * Method to generate a Signed CRL.
	 * 
	 * 
	 * @param contents the CRL content to sign.
	 * @param signerIdentifierType type of signer identifier to include, one of SignerIdentifierType
	 * @param signerCertificateChain the complete chain up to the trust anchor. Important the trust anchor MUST be an explicit certificate and the array
	 * must be in the order of end entity certificate at position 0 and trust anchor last in array.
	 * @param signerPrivateKey private key of signer.
	 * @return a signed secured CRL structure.
	 * 
	 * @throws BadArgumentException if fault was discovered in supplied parameters.
	 * @throws SignatureException if internal problems occurred generating the signature.
	 * @throws IOException if IO exception occurred communicating with underlying systems. 
	 */
	public SecuredCrl genSecuredCrl(CrlContents contents, SignerIdentifierType signerIdentifierType, Certificate[] signerCertificateChain, PrivateKey signerPrivateKey) throws BadArgumentException, SignatureException, IOException{
		HeaderInfo hi = new HeaderInfo(new CrlPsid(), null, null, null, null, null, null, null,null);
		return new SecuredCrl(genSignedData(hi, contents.getEncoded(), signerIdentifierType, signerCertificateChain, signerPrivateKey));
	}

	/**
	 * Method to verify signature of a signed CRL. This method only checks the signature, not validity or any other fields.
	 * 
	 * @param crl the CRL to verify.
     * @param certStore a list of known certificates that can be used to build a certificate path (excluding trust anchors).
     * @param trustStore certificates in trust store, must be explicit certificate in order to qualify as trust anchors.
     * @return true if crl signature verifies.
     * 
	 * @throws BadArgumentException if fault was discovered in supplied parameters.
	 * @throws SignatureException if internal problems occurred verifying the signature.
	 * @throws IOException if IO exception occurred communicating with underlying systems. 
	 */
	public boolean verifySecuredCrl(SecuredCrl crl, CertStore certStore, CertStore trustStore) throws BadArgumentException, SignatureException, IOException{
		return verifySignedData(crl, certStore, trustStore);
	}
		
}

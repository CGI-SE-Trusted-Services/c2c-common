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
package org.certificateservices.custom.c2x.its.datastructs.basic;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.its.crypto.ITSCryptoManager;
import org.certificateservices.custom.c2x.its.datastructs.cert.Certificate;


/**
 * This value is used to give an indication on an identifier, where real identification is not required. This can be used to
 * request a certificate from other surrounding stations. It shall be calculated by first computing the SHA-256 hash of the
 * input data, and then taking the least significant three bytes from the hash output. If a corresponding HashedId8 value
 * is available, it can be calculated by truncating the longer HashedId8 to the least significant three bytes.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class HashedId3 extends HashedId{
	
	/**
	 * Method to Create a normalised version of HasheId id of certificate that replaces R point that is not x_coordinate_only
	 * A canonical encoding for the EccPoint R contained in the signature field of a Certificate shall be used
	 * when calculating the SHA-256 hash from a Certificate. This canonical encoding shall temporarily replace the
	 * value of the EccPointType of the point R of the Certificate with x_coordinate_only for the hash
	 * computation.
	 * 
	 * @param certifiate the certificate to calculate hash on.
	 * @param cryptoManager the related crypto manager.
	 * @throws IllegalArgumentException if supplied argumets was invalid.
	 * @throws IOException if communication problems occurred generating the request.
	 * @throws InvalidKeySpecException if certificate has invalid key values in signature.
	 * @throws NoSuchAlgorithmException if related hash algorithm doesn't exist in system. 
	 */
	public HashedId3(Certificate certifiate, ITSCryptoManager cryptoManager) throws IllegalArgumentException, IOException, InvalidKeySpecException, NoSuchAlgorithmException {
		super(certifiate,cryptoManager);
	}
	
	/**
	 * Main constructor for a HashId taking the three least significant bytes in it's hash value.
	 * 
	 * @param fullHashValue the full hash value.
	 */
	public HashedId3(byte[] fullHashValue){
		super(fullHashValue);
	}
	
	/**
	 * Constructor used during serializing.
	 * 
	 */
	public HashedId3(){
		super();
	}

	/**
	 * Indicates this is an eight octet hashId
	 */
	@Override
	protected int getHashLength() {
		return 3;
	}

	@Override
	public String toString() {
		return "HashedId3 [" + new String(Hex.encode(hashedId)) + "]";
	}
	

}

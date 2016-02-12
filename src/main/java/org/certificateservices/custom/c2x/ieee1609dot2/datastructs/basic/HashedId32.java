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
package org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic;

import org.bouncycastle.util.encoders.Hex;

/**
 * This data structure contains the truncated hash of another data structure. The HashedId32 for a given data
 * structure is calculated by calculating the SHA-256 hash of the encoded data structure and taking the low-
 * order three bytes of the hash output. The low-order three bytes are the last three bytes of the 32-byte hash.
 * 
 * <b>ENCODING CONSIDERATIONS:</b> If the data structure is a Certificate, the encoded Certificate which is
 * input to the hash uses the compressed form for all elliptic curve points within the ToBeSignedCertificate
 * and takes the r value of an ECDSA signature to be of type x-only. If the data structure is a Ieee1609-
 * Dot2Data containing a SignedData, the encoding takes the r value of an ECDSA signature to be of type x-
 * only.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class HashedId32 extends HashedId {

	private static final long serialVersionUID = 1L;
	
	/**
	 * Constructor used during decoding.
	 * 
	 */
	public HashedId32() {
		super();
	}
	
	/**
	 * Constructor used to create a hashedid32 value for a full hash byte array.
	 * @param fullHashValue the fill hash value.
	 * @throws IllegalArgumentException if full hash value was shorted that hash length
	 */
	public HashedId32(byte[] fullHashValue) throws IllegalArgumentException {
		super(fullHashValue);
	}

	@Override
	protected int getHashLength() {
		return 32;
	}

	@Override
	public String toString() {
		return "HashedId32 [" + new String(Hex.encode(data)) + "]";
	}
	
}

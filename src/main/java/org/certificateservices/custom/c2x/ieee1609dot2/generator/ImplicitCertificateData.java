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
import java.math.BigInteger;

import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.IssuerIdentifier;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.ToBeSignedCertificate;

/**
 * Special case of generated structure containing a implicit certificate along with the r value used to construct the related private key.
 * The r value is not a part of the encoding when calling getEncoded() but has to handled separately. 
 * 
 * @author Philip Vendil
 *
 */
public class ImplicitCertificateData extends Certificate {
	

	private static final long serialVersionUID = 1L;
	
	private BigInteger r;
	
	/**
	 * Method used when decoding, important r value is not part of any decoding, must be handled separately.
	 */
	public ImplicitCertificateData() {
		super();
	}

	/**
	 * Method used when decoding, important r value is not part of any decoding, must be handled separately.
	 */
	public ImplicitCertificateData(byte[] encodedCert) throws IOException {
		super(encodedCert);
	}

	/**
	 * Method used when encoding, important r value is not part of any encoding, must be handled separately.
	 * 
	 * @see Certificate#Certificate(int,IssuerIdentifier, ToBeSignedCertificate)
	 */
	public ImplicitCertificateData(int version, IssuerIdentifier issuer,
			ToBeSignedCertificate toBeSigned) throws IOException {
		super(version, issuer, toBeSigned);
	}

	/**
	 * Method used when encoding, important r value is not part of any encoding, must be handled separately.
	 * 
	 * @see Certificate#Certificate(IssuerIdentifier, ToBeSignedCertificate)
	 */
	public ImplicitCertificateData(IssuerIdentifier issuer,
			ToBeSignedCertificate toBeSigned) throws IOException {
		super(issuer, toBeSigned);
	}

	/**
	 * 
	 * @return the related r value used to reconstruct the private key.
	 */
	public BigInteger getR(){
		return r;
	}

	/**
	 * 
	 * @param r the related r value used to reconstruct the private key.
	 */
	public void setR(BigInteger r){
		this.r = r;
	}
	

}

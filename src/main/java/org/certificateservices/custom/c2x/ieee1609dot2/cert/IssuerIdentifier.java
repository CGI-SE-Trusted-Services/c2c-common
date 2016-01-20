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
package org.certificateservices.custom.c2x.ieee1609dot2.cert;

import java.io.IOException;

import org.certificateservices.custom.c2x.asn1.coer.COERChoice;
import org.certificateservices.custom.c2x.asn1.coer.COERChoiceEnumeration;
import org.certificateservices.custom.c2x.asn1.coer.COEREncodable;
import org.certificateservices.custom.c2x.asn1.coer.COEREnumeration;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.HashAlgorithm;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.HashedId8;

/**
 * This structure allows the recipient of a certificate to determine which keying material to use to authenticate
 * the certificate.
 * <li>If the choice indicated is sha256AndDigest:
 * <br>
 * -The structure contains the HashedId8 of the issuing certificate, obtained as specified in the description of the HashedId8 structure.
 * <br>
 * -The hash algorithm to be used to generate the hash of the certificate for verification is SHA- 256.
 * <br>
 * -The certificate is to be verified with the public key of the indicated issuing certificate.
 * <li>If the choice indicated is self:
 * <br>
 * -The structure indicates what hash algorithm is to be used to generate the hash of the certificate for verification.
 * <br>
 * -The certificate is to be verified with the public key indicated by the verifyKeyIndicator field in theToBeSignedCertificate.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class IssuerIdentifier extends COERChoice {
	
	
	private static final long serialVersionUID = 1L;
	
	public enum IssuerIdentifierChoices implements COERChoiceEnumeration{
		sha256AndDigest,
		self;

		@Override
		public COEREncodable getEmptyCOEREncodable() throws IOException {
			switch (this) {
			case sha256AndDigest:
				return new HashedId8();
			case self:
			default:
				return new COEREnumeration(HashAlgorithm.class);
			}
		}
	}
	
	/**
	 * Constructor used when encoding of type linkageData
	 */
	public IssuerIdentifier(HashedId8 sha256AndDigest) throws IllegalArgumentException{
		super(IssuerIdentifierChoices.sha256AndDigest, sha256AndDigest);
	}
	
	/**
	 * Constructor used when encoding of type self
	 */
	public IssuerIdentifier(HashAlgorithm hashAlgorithm) throws IllegalArgumentException{
		super(IssuerIdentifierChoices.self, new COEREnumeration(hashAlgorithm));
	}
	
	/**
	 * Constructor used when decoding
	 */
	public IssuerIdentifier(){
		super(IssuerIdentifierChoices.class);
	}
			
	/**
	 * Returns the type of id.
	 */
	public IssuerIdentifierChoices getType(){
		return (IssuerIdentifierChoices) choice;
	}
	
	public HashAlgorithm getHashAlgoritm(){
		if(getType() == IssuerIdentifierChoices.self){
			return (HashAlgorithm) ((COEREnumeration) getValue()).getValue();
		}
		return null;
	}

	@Override
	public String toString() {
		switch(getType()){
		  case sha256AndDigest:
			  return "IssuerIdentifier [" + choice + "=" + value.toString().replace("HashedId8 ", "") +"]";
		  case self:
			  default:
			return "IssuerIdentifier [" + choice + "=" + getHashAlgoritm().toString() +"]";
		}
	}
	
}

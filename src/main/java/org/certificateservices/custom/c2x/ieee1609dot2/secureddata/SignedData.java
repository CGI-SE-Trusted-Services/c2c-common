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
package org.certificateservices.custom.c2x.ieee1609dot2.secureddata;

import org.certificateservices.custom.c2x.asn1.coer.COEREnumeration;
import org.certificateservices.custom.c2x.asn1.coer.COERSequence;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.HashAlgorithm;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Signature;

/**
 * In this structure: 
 * <li>hashId indicates the hash algorithm to be used to generate the hash of the message for signing and verification.
 * <li>tbsData contains the data that is hashed as input to the signature.
 * <li>signer determines the keying material and hash algorithm used to sign the data. 
 * <li>signature contains the digital signature itself, calculated as specified in 5.3.1, with:
 * <br>- Data input equal to the COER encoding of the tbsData field canonicalized according to the encoding considerations given in 6.3.6,
 * <br>- Verification type equal to certificate,
 * <br>- Signer identifier input equal to the COER-encoding of the Certificate that is to be used to
 * verify the SPDU, canonicalized according to the encoding considerations given in 6.4.3.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class SignedData extends COERSequence {
	

	private static final long serialVersionUID = 1L;
	
	private static final int HASHID = 0;
	private static final int TBSDATA = 1;
	private static final int SIGNER = 2;
	private static final int SIGNATURE = 3;

	/**
	 * Constructor used when decoding
	 */
	public SignedData(){
		super(false,4);
		init();
	}
	
	/**
	 * Constructor used when encoding
	 */
	public SignedData(HashAlgorithm hashAlgorithm, ToBeSignedData tbsData, SignerIdentifier signer, Signature signature){
		super(false,4);
		init();
		if(hashAlgorithm == null){
			throw new IllegalArgumentException("Error argument hashAlgorithm cannot be null for SignedData.");
		}
		set(HASHID, new COEREnumeration(hashAlgorithm));
		set(TBSDATA, tbsData);
		set(SIGNER, signer);
		set(SIGNATURE, signature);
	}

	/**
	 * 
	 * @return hashAlgorithm
	 */
	public HashAlgorithm getHashAlgorithm(){
		return (HashAlgorithm) ((COEREnumeration) get(HASHID)).getValue();
	}
	
	/**
	 * 
	 * @return tbsData
	 */
	public ToBeSignedData getTbsData(){
		return (ToBeSignedData) get(TBSDATA);
	}
	
	/**
	 * 
	 * @return signer
	 */
	public SignerIdentifier getSigner(){
		return (SignerIdentifier) get(SIGNER);
	}
	
	/**
	 * 
	 * @return signature
	 */
	public Signature getSignature(){
		return (Signature) get(SIGNATURE);
	}
	
	private void init(){
		addField(HASHID, false, new COEREnumeration(HashAlgorithm.class), null);
		addField(TBSDATA, false, new ToBeSignedData(), null);
		addField(SIGNER, false, new SignerIdentifier(), null);
		addField(SIGNATURE, false, new Signature(), null);
	}
	
	@Override
	public String toString() {
		return "SignedData [\n"+
	    "  hashAlgorithm=" + getHashAlgorithm() +  ",\n"+
		"  tbsData=" + getTbsData().toString().replace("ToBeSignedData ", "").replaceAll("\n", "\n  ") +  ",\n" +
		"  signer=" + getSigner().toString().replace("SignerIdentifier ", "").replaceAll("\n", "\n  ") +  ",\n" +
		"  signature=" + getSignature().toString().replace("Signature ", "") +  "\n" +
	    "]";
	}
	
}

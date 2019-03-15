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
import org.certificateservices.custom.c2x.asn1.coer.COEROctetStream;
import org.certificateservices.custom.c2x.asn1.coer.COERSequence;

/**
 * This structure represents an ECDSA signature. The signature is generated as specified in 5.3.1.
 * <p>
 * If the signature process followed the specification of FIPS 186-4 and output the integer r, r is represented
 * as an EccP384CurvePoint indicating the selection x-only.
 * </p>
 * <p>
 * If the signature process followed the specification of SEC 1 and output the elliptic curve point R to allow for 
 * fast verification, R is represented as an EccP384CurvePoint indicating the choice compressed-y-0, compressed-y-1,
 * or uncompressed at the sender’s discretion
 * </p>
 * <p>
 * <b>Encoding considerations:</b> If this structure is encoded for hashing, the EccP384CurvePoint in rSig shall
 * be taken to be of form x-only.
 * </p>
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class EcdsaP384Signature extends COERSequence {

	private static final int OCTETSTRING_SIZE = 48;

	private static final long serialVersionUID = 1L;

	private static final int R = 0;
	private static final int S = 1;

	/**
	 * Constructor used when decoding
	 */
	public EcdsaP384Signature(){
		super(false,2);
		init();
	}

	/**
	 * Constructor used when encoding
	 */
	public EcdsaP384Signature(EccP384CurvePoint r, byte[] s){
		super(false,2);
		init();
		if(s == null){
			throw new IllegalArgumentException("Error s value cannot be null in EcdsaP384Signature");
		}
		set(R, r);
		set(S, new COEROctetStream(s, OCTETSTRING_SIZE, OCTETSTRING_SIZE));
	}

	/**
	 * 
	 * @return r value
	 */
	public EccP384CurvePoint getR(){
		return (EccP384CurvePoint) get(R);
	}
	
	/**
	 * 
	 * @return the 32 byte s value
	 */
	public byte[] getS(){
		return ((COEROctetStream) get(S)).getData();
	}
	
	private void init(){
		addField(R, false, new EccP384CurvePoint(), null);
		addField(S, false, new COEROctetStream(OCTETSTRING_SIZE, OCTETSTRING_SIZE), null);
	}
	
	@Override
	public String toString() {
		return "EcdsaP384Signature [r=" + getR().toString().replaceAll("EccP384CurvePoint ", "") + ", s=" + new String(Hex.encode(getS())) + "]";
	}
	
}

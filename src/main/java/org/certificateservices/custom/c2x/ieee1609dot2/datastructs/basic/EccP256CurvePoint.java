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

import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.asn1.coer.COERChoice;
import org.certificateservices.custom.c2x.asn1.coer.COERChoiceEnumeration;
import org.certificateservices.custom.c2x.asn1.coer.COEREncodable;
import org.certificateservices.custom.c2x.asn1.coer.COEREncodeHelper;
import org.certificateservices.custom.c2x.asn1.coer.COEROctetStream;

/**
 * This structure specifies a point on an elliptic curve in Weierstrass form defined over a 256-bit prime number. This encompasses both NIST p256 as defined in FIPS 186-4 and 
 * Brainpool p256r1 as defined in RFC 5639. The fields in this structure are OCTET STRINGS produced with the elliptic curve point encoding and decoding methods defined in 
 * IEEE Std 1363-2000 clause 5.5.6. The x-coordinate is encoded as an unsigned integer of length 32 octets in network byte order for all values of the CHOICE; the encoding 
 * of the y-coordinate y depends on whether the point is x-only, compressed, or uncompressed. If the point is x-only, y is omitted. If the point is compressed, the value of 
 * type depends on the LSB of y: if the LSB of y is 0, type takes the value compressed-y-0, and if the LSB of y is 1, type takes the value compressed-y-1. If the point is 
 * uncompressed, y is encoded explicitly as an unsigned integer of length 32 octets in network byte order.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class EccP256CurvePoint extends COERChoice {
	
	private static final int OCTETSTRING_SIZE = 32;
	
	private static final long serialVersionUID = 1L;
	
	public enum EccP256CurvePointChoices implements COERChoiceEnumeration{
		xonly,
		fill, // Not used
		compressedy0,
		compressedy1,
		uncompressed;

		@Override
		public COEREncodable getEmptyCOEREncodable() throws IOException {
			if(this.equals(uncompressed)){
				return new UncompressedEccPoint();
			}
			return new COEROctetStream(OCTETSTRING_SIZE,OCTETSTRING_SIZE);
		}
	}
	
	/**
	 * Constructor used when encoding of type xonly as BigInteger
	 */
	public EccP256CurvePoint(BigInteger x) {
		super(EccP256CurvePointChoices.xonly, new COEROctetStream(COEREncodeHelper.padZerosToByteArray(fromBigInteger(x),OCTETSTRING_SIZE),OCTETSTRING_SIZE,OCTETSTRING_SIZE));
	}
	
	
	/**
	 * Constructor used when encoding of type compressedy0 or compressedy1
	 */
	public EccP256CurvePoint(byte[] compressedEncoding) {
		super(getChoice(compressedEncoding), new COEROctetStream(COEREncodeHelper.padZerosToByteArray(removeFirstByte(compressedEncoding), OCTETSTRING_SIZE), OCTETSTRING_SIZE,OCTETSTRING_SIZE));
	}
	



	/**
	 * Constructor used when encoding of type uncompressed
	 */
	public EccP256CurvePoint(byte[] uncompressed_x, byte[] uncompressed_y) {
		super(EccP256CurvePointChoices.uncompressed, new UncompressedEccPoint(uncompressed_x, uncompressed_y));
	}
	
	/**
	 * Constructor used when encoding of type uncompressed
	 */
	public EccP256CurvePoint(BigInteger uncompressed_x, BigInteger uncompressed_y) {
		super(EccP256CurvePointChoices.uncompressed, new UncompressedEccPoint(fromBigInteger(uncompressed_x), fromBigInteger(uncompressed_y)));
	}	

	/**
	 * Constructor used when decoding.
	 */
	public EccP256CurvePoint() {
		super(EccP256CurvePointChoices.class);
	}
		
	/**
	 * Returns the type of point.
	 */
	public EccP256CurvePointChoices getType(){
		return (EccP256CurvePointChoices) choice;
	}

	@Override
	public String toString() {
		if(choice == EccP256CurvePointChoices.uncompressed){
			return "EccP256CurvePoint [" + choice + "=" +  value.toString().replace("UncompressedEccPoint ", "") + "]";	
		}
		return "EccP256CurvePoint [" + choice + "=" +  new String(Hex.encode(((COEROctetStream) value).getData())) + "]";
	}
	
	
	private static byte[] fromBigInteger(BigInteger v){
		byte[] data = v.toByteArray();
		if(data.length > OCTETSTRING_SIZE){
			byte[] d = new byte[OCTETSTRING_SIZE];
			System.arraycopy(data, data.length - OCTETSTRING_SIZE, d,0, OCTETSTRING_SIZE);
			return d;
		}
		return data;
	}
	
	private static byte[] removeFirstByte(byte[] compressedEncoding) {
		if(compressedEncoding == null || compressedEncoding.length < 1){
			throw new IllegalArgumentException("Invalid compressed encoding of EccP256CurvePoint");
		}
		byte[] retval = new byte[compressedEncoding.length -1];
		System.arraycopy(compressedEncoding, 1, retval, 0,retval.length);
		return retval;
	}


	private static COERChoiceEnumeration getChoice(byte[] compressedEncoding) {
		if(compressedEncoding[0] == 0x02){
			return EccP256CurvePointChoices.compressedy0;
		}
		if(compressedEncoding[0] == 0x03){
			return EccP256CurvePointChoices.compressedy1;
		}
		throw new IllegalArgumentException("Invalid Ecc Point compressed encoding");
	}
}

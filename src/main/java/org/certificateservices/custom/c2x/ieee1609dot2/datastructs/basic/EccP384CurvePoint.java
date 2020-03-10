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
import org.certificateservices.custom.c2x.asn1.coer.*;

import java.io.IOException;
import java.math.BigInteger;

/**
 * This structure specifies a point on an elliptic curve in Weierstrass form defined over a 384-bit prime
 * number. The only supported such curve in this standard is Brainpool p384r1 as defined in RFC 5639. The
 * fields in this structure are OCTET STRINGS produced with the elliptic curve point encoding and decoding
 * methods defined in subclause 5.5.6 of IEEE Std 1363-2000. The x-coordinate is encoded as an unsigned
 * integer of length 48 octets in network byte order for all values of the CHOICE; the encoding of the ycoordinate
 * y depends on whether the point is x-only, compressed, or uncompressed. If the point is x-only, y
 * is omitted. If the point is compressed, the value of type depends on the least significant bit of y: if the
 * least significant bit of y is 0, type takes the value compressed-y-0, and if the least significant bit of y is
 * 1, type takes the value compressed-y-1. If the point is uncompressed, y is encoded explicitly as an
 * unsigned integer of length 48 octets in network byte order.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class EccP384CurvePoint extends EccCurvePoint {

	private static final int OCTETSTRING_SIZE = 48;

	private static final long serialVersionUID = 1L;

	public enum EccP384CurvePointChoices implements COERChoiceEnumeration{
		xonly,
		fill, // Not used
		compressedy0,
		compressedy1,
		uncompressed;

		@Override
		public COEREncodable getEmptyCOEREncodable() throws IOException {
			if(this.equals(uncompressed)){
				return new UncompressedEccPoint(OCTETSTRING_SIZE);
			}
			return new COEROctetStream(OCTETSTRING_SIZE,OCTETSTRING_SIZE);
		}

		/**
		 * @return no extensions exists, always false.
		 */
		@Override
		public boolean isExtension() {
			return false;
		}
	}

	/**
	 * Constructor used when encoding of type xonly as BigInteger
	 */
	public EccP384CurvePoint(BigInteger x) throws IOException {
		super(EccP384CurvePointChoices.xonly, new COEROctetStream(COEREncodeHelper.padZerosToByteArray(fromBigInteger(x),OCTETSTRING_SIZE),OCTETSTRING_SIZE,OCTETSTRING_SIZE));
	}


	/**
	 * Constructor used when encoding of type compressedy0 or compressedy1, or encoded uncompressed
	 */
	public EccP384CurvePoint(byte[] encoded) throws IOException {
		super(EccP384CurvePointChoices.class);
		EccP384CurvePointChoices type = getChoice(encoded);
		choice = type;
		if(type == EccP384CurvePointChoices.uncompressed){
			byte[] x = new byte[OCTETSTRING_SIZE];
			System.arraycopy(encoded, 1, x, 0, OCTETSTRING_SIZE);
			byte[] y = new byte[OCTETSTRING_SIZE];
			System.arraycopy(encoded, OCTETSTRING_SIZE+1, y, 0, OCTETSTRING_SIZE);
			value = new UncompressedEccPoint(OCTETSTRING_SIZE,x,y);
		}else{
		  value = new COEROctetStream(COEREncodeHelper.padZerosToByteArray(removeFirstByte(encoded), OCTETSTRING_SIZE), OCTETSTRING_SIZE,OCTETSTRING_SIZE);
		}
	}




	/**
	 * Constructor used when encoding of type uncompressed
	 */
	public EccP384CurvePoint(byte[] uncompressed_x, byte[] uncompressed_y) throws IOException {
		super(EccP384CurvePointChoices.uncompressed, new UncompressedEccPoint(OCTETSTRING_SIZE,uncompressed_x, uncompressed_y));
	}

	/**
	 * Constructor used when encoding of type uncompressed
	 */
	public EccP384CurvePoint(BigInteger uncompressed_x, BigInteger uncompressed_y) throws IOException {
		super(EccP384CurvePointChoices.uncompressed, new UncompressedEccPoint(OCTETSTRING_SIZE,fromBigInteger(uncompressed_x), fromBigInteger(uncompressed_y)));
	}

	/**
	 * Constructor used when decoding.
	 */
	public EccP384CurvePoint() {
		super(EccP384CurvePointChoices.class);
	}
		
	/**
	 * Returns the type of point.
	 */
	public EccP384CurvePointChoices getType(){
		return (EccP384CurvePointChoices) choice;
	}

	@Override
	public String toString() {
		if(choice == EccP384CurvePointChoices.uncompressed){
			return "EccP384CurvePoint [" + choice + "=" +  value.toString().replace("UncompressedEccPoint ", "") + "]";	
		}
		return "EccP384CurvePoint [" + choice + "=" +  new String(Hex.encode(((COEROctetStream) value).getData())) + "]";
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
	
	private static byte[] removeFirstByte(byte[] compressedEncoding) throws IOException{
		if(compressedEncoding == null || compressedEncoding.length < 1){
			throw new IOException("Invalid compressed encoding of EccP384CurvePoint");
		}
		byte[] retval = new byte[compressedEncoding.length -1];
		System.arraycopy(compressedEncoding, 1, retval, 0,retval.length);
		return retval;
	}


	private static EccP384CurvePointChoices getChoice(byte[] compressedEncoding) throws IOException{
		if(compressedEncoding[0] == 0x02){
			return EccP384CurvePointChoices.compressedy0;
		}
		if(compressedEncoding[0] == 0x03){
			return EccP384CurvePointChoices.compressedy1;
		}
		if(compressedEncoding[0] == 0x04){
			return EccP384CurvePointChoices.uncompressed;
		}
		throw new IOException("Invalid Ecc Point compressed encoding");
	}
}

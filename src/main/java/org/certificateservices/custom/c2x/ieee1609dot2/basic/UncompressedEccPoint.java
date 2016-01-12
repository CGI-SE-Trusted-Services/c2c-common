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
package org.certificateservices.custom.c2x.ieee1609dot2.basic;

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.asn1.coer.COEREncodeHelper;
import org.certificateservices.custom.c2x.asn1.coer.COEROctetStream;
import org.certificateservices.custom.c2x.asn1.coer.COERSequence;

/**
 * This data structure representing the x and y coordinates of a ECC Point
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class UncompressedEccPoint extends COERSequence {
	
	private static final int OCTETSTRING_SIZE = 32;
	
	private static final long serialVersionUID = 1L;
	
	private static final int X = 0;
	private static final int Y = 1;

	/**
	 * Constructor used when decoding
	 */
	public UncompressedEccPoint(){
		super(false,2);
		init();
	}
	
	/**
	 * Constructor used when encoding
	 * @param x 32 byte coordinate
	 * @param y 32 byte coordinate
	 */
	public UncompressedEccPoint(byte[] x, byte[] y){
		super(false,2);
		init();
		x = normaliseLength(x);
		y = normaliseLength(y);
		set(X, new COEROctetStream(x, OCTETSTRING_SIZE, OCTETSTRING_SIZE));
		set(Y, new COEROctetStream(y, OCTETSTRING_SIZE, OCTETSTRING_SIZE));
		
	}



	/**
	 * 
	 * @return x 32 byte coordinate
	 */
	public byte[] getX(){
		return ((COEROctetStream) get(X)).getData();
	}
	
	/**
	 * 
	 * @return y 32 byte coordinate
	 */
	public byte[] getY(){
		return ((COEROctetStream) get(Y)).getData();
	}
	

	private void init(){
		addField(X, false, new COEROctetStream(OCTETSTRING_SIZE, OCTETSTRING_SIZE), null);
		addField(Y, false, new COEROctetStream(OCTETSTRING_SIZE, OCTETSTRING_SIZE), null);
	}
	
	@Override
	public String toString() {
		return "UncompressedEccPoint [x=" + new String(Hex.encode(getX())) + ", y=" + new String(Hex.encode(getY())) + "]";
	}
	
	/**
	 * Pad zeros in beginning of array to make sure it's 32 bytes
	 */
	private byte[] normaliseLength(byte[] data) {
		return COEREncodeHelper.padZerosToByteArray(data, OCTETSTRING_SIZE);
	}
	
}

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
import org.certificateservices.custom.c2x.asn1.coer.COEREncodeHelper;
import org.certificateservices.custom.c2x.asn1.coer.COEROctetStream;
import org.certificateservices.custom.c2x.asn1.coer.COERSequence;

import java.io.IOException;

/**
 * This data structure representing the x and y coordinates of a ECC Point
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class UncompressedEccPoint extends COERSequence {

	private static final long serialVersionUID = 1L;
	
	private static final int X = 0;
	private static final int Y = 1;

	private static int octetSize;

	/**
	 * Constructor used when decoding
	 *
	 * @param octetSize the size of the data in the EC Point, depends on curve used. 32 for EC P-256 and 48 for EC P-384.
	 */
	public UncompressedEccPoint(int octetSize){
		super(false,2);
		this.octetSize = octetSize;
		init();
	}
	
	/**
	 * Constructor used when encoding
	 * @param octetSize the size of the data in the EC Point, depends on curve used. 32 for EC P-256 and 48 for EC P-384.
	 * @param x 32 byte coordinate
	 * @param y 32 byte coordinate
	 */
	public UncompressedEccPoint(int octetSize, byte[] x, byte[] y) throws IOException {
		super(false,2);
		init();
		this.octetSize = octetSize;
		x = normaliseLength(x);
		y = normaliseLength(y);
		set(X, new COEROctetStream(x, octetSize, octetSize));
		set(Y, new COEROctetStream(y, octetSize, octetSize));
		
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
		addField(X, false, new COEROctetStream(octetSize, octetSize), null);
		addField(Y, false, new COEROctetStream(octetSize, octetSize), null);
	}
	
	@Override
	public String toString() {
		return "UncompressedEccPoint [x=" + new String(Hex.encode(getX())) + ", y=" + new String(Hex.encode(getY())) + "]";
	}
	
	/**
	 * Pad zeros in beginning of array to make sure it's 32 bytes
	 */
	private byte[] normaliseLength(byte[] data) {
		return COEREncodeHelper.padZerosToByteArray(data, octetSize);
	}
	
}

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
import org.certificateservices.custom.c2x.asn1.coer.COEROctetStream;

/**
 * Base type defining opaque data, i.e. unknown byte array with no lower or upper bounds.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class Opaque extends COEROctetStream {
	
	private static final long serialVersionUID = 1L;
	
	/**
	 * Constructor used when decoding
	 */
	public Opaque(){
		super();
	}
	
	/**
	 * Constructor used when encoding
	 */
	public Opaque(byte[] data){
		super(data);
	}

	@Override
	public String toString() {
		return "Opaque [data=" + new String(Hex.encode(data)) + "]";
	}
	
	

}

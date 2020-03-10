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

/**
 * 16 bit Integer
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class IValue extends Uint16 {
	
	private static final long serialVersionUID = 1L;
	
	/**
	 * Constructor used when decoding
	 */
	public IValue(){
		super();
	}
	
	/**
	 * Constructor used when encoding
	 */
	public IValue(int ivalue) throws IOException {
		super(ivalue);		
	}
	
	@Override
	public String toString() {
		return "IValue [" + getValueAsLong() + "]";
	}
}

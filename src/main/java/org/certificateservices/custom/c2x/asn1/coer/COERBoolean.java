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
package org.certificateservices.custom.c2x.asn1.coer;


import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

/**
 * COER encoding of a boolean.
 * <p>
 * For more information see ISO/IEC 8825-7:2015 Section 9
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class COERBoolean implements COEREncodable{
	
	private static final long serialVersionUID = 1L;
	
	public static COERBoolean TRUE = new COERBoolean(true);
	public static COERBoolean FALSE = new COERBoolean(false);
	
	private static final int TRUE_ENCODED = 0xFF;
	private static final int FALSE_ENCODED = 0x00;

	private boolean value;
	
	/**
	 * Constructor used when decoding a COER boolean.
	 */
	public COERBoolean(){
	}
	
	/**
	 * Constructor used when encoding a COER boolean.
	 */
	public COERBoolean(boolean value) {
		this.value = value;
	}

	/**
	 * 
	 * @return the boolean value.
	 */
	public boolean isValue() {
		return value;
	}	

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + (value ? 1231 : 1237);
		return result;
	}



	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		COERBoolean other = (COERBoolean) obj;
		if (value != other.value)
			return false;
		return true;
	}


	@Override
	public void encode(DataOutputStream out) throws IOException {
		if(value){
		  out.write(TRUE_ENCODED);
		}else{
		  out.write(FALSE_ENCODED);
		}
		
	}

	@Override
	public void decode(DataInputStream in) throws IOException {
		int val = in.read();
		if(val == TRUE_ENCODED){
			value = true;
		}else if(val == FALSE_ENCODED){
			value = false;
		}else{
			throw new IOException("Illegal boolean value: " + val + " in COER encoding");
		}
	}


	@Override
	public String toString() {
		return "COERBoolean [value=" + value + "]";
	}
}

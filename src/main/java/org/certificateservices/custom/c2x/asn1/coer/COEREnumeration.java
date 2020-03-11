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
 * COER encoding of an enumeration.
 * <p> 
 * For more information see ISO/IEC 8825-7:2015.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class COEREnumeration implements COEREncodable{
	
	private static final long serialVersionUID = 1L;
	
	protected Class<?> coerEnum;
	protected COEREnumerationType enumerationValue;

	
	/**
	 * Constructor used when decoding a COER Enumeration.
	 * 
	 * @param coerEnum the class of the enum that implements COEREnumerationType
	 */
	public COEREnumeration(Class<?> coerEnum){
		this.coerEnum = coerEnum;
	}
	
	/**
	 * Constructor used when encoding a COER Choice.
	 * 
	 * @param enumerationValue a enum value of an enumeration implementing COEREnumerationType
	 */
	public COEREnumeration(COEREnumerationType enumerationValue){
		this.enumerationValue = enumerationValue;
	}


	/**
	 * 
	 * @return the related.
	 */
	public COEREnumerationType getValue() {
		return enumerationValue;
	}

	@Override
	public void encode(DataOutputStream out) throws IOException {

			COEREncodeHelper.writeEnumerationValue(enumerationValue, out);
	}

	@SuppressWarnings("unchecked")
	@Override
	public void decode(DataInputStream in) throws IOException {
		enumerationValue = COEREncodeHelper.readEnumeratonValueAsEnumeration((Class<COEREnumerationType>) coerEnum, in);
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((enumerationValue == null) ? 0 : enumerationValue.hashCode());
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
		COEREnumeration other = (COEREnumeration) obj;
		if (enumerationValue == null) {
			if (other.enumerationValue != null)
				return false;
		} else if (!enumerationValue.equals(other.enumerationValue))
			return false;
		return true;
	}

	@Override
	public String toString() {
		return "COEREnumeration [value=" + enumerationValue + "]";
	}

}

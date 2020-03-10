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

import java.io.IOException;

/**
 * This is the group linkage value. See 5.1.3 and 7.3 for details of use.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class GroupLinkageValue extends COERSequence {
	
	private static final int JVALUE_SIZE = 4;
	private static final int VALUE_SIZE = 9;
	
	private static final long serialVersionUID = 1L;
	
	private static final int JVALUE = 0;
	private static final int VALUE = 1;

	/**
	 * Constructor used when decoding
	 */
	public GroupLinkageValue(){
		super(false,2);
		init();
	}
	
	/**
	 * Constructor used when encoding
	 */
	public GroupLinkageValue(byte[] jValue, byte[] value) throws IOException {
		super(false,2);
		init();
		if(jValue != null && jValue.length != JVALUE_SIZE){
			throw new IOException("Error JValue must be " + JVALUE_SIZE + " bytes.");
		}
		if(value != null && value.length != VALUE_SIZE){
			throw new IOException("Error value must be " + VALUE_SIZE + " bytes.");
		}
		set(JVALUE, new COEROctetStream(jValue, JVALUE_SIZE, JVALUE_SIZE));
		set(VALUE, new COEROctetStream(value, VALUE_SIZE, VALUE_SIZE));
	}

	/**
	 * 
	 * @return jvalue
	 */
	public byte[] getJValue(){
		return ((COEROctetStream) get(JVALUE)).getData();
	}
	
	/**
	 * 
	 * @return value
	 */
	public byte[] getValue(){
		return ((COEROctetStream) get(VALUE)).getData();
	}
	
	private void init(){
		addField(JVALUE, false, new COEROctetStream(JVALUE_SIZE, JVALUE_SIZE), null);
		addField(VALUE, false, new COEROctetStream(VALUE_SIZE, VALUE_SIZE), null);
	}
	
	@Override
	public String toString() {
		return "GroupLinkageValue [jvalue=" + new String(Hex.encode(getJValue()))+ ", value=" +  new String(Hex.encode(getValue())) + "]";
	}
	
}

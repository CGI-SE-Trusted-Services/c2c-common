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

import org.certificateservices.custom.c2x.common.Encodable;

public enum TestCOEREnumeration implements COERChoiceEnumeration {
	CHOICE1(new COERInteger(0,8)),
	CHOICE2(new COEROctetStream()),
	CHOICE3(new COERInteger(0,10));

	private COEREncodable emptyCOEREncodable;
	private TestCOEREnumeration(COEREncodable emptyCOEREncodable){
		this.emptyCOEREncodable = emptyCOEREncodable;
	}
	
	@Override
	public COEREncodable getEmptyCOEREncodable() throws IOException{
		try{
			return emptyCOEREncodable.clone();
		}catch(CloneNotSupportedException e){
			throw new IOException("Error cloning COER encodable: " + emptyCOEREncodable);
		}
	}

}

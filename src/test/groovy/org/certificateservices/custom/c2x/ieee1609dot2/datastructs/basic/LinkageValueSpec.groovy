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
package org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic

import java.security.MessageDigest

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.common.BaseStructSpec;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.LinkageValue;

import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for LinkageValue
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class LinkageValueSpec extends BaseStructSpec {
	
	byte[] linkagevalue  = Hex.decode("010203040506070809")
	


	
	def "Verify that LinkageValue stores the data correctly"(){
		when:
		LinkageValue h1 = new LinkageValue(linkagevalue)
		then:
		h1.getLinkageValue() == linkagevalue; // verify the methods returns the same data
		h1.getLinkageValue().length == 9
		serializeToHex(h1) == "010203040506070809"
		
		when:
		LinkageValue h2 = deserializeFromHex(new LinkageValue(), "010203040506070809")
		then:
		h2.getLinkageValue() == linkagevalue
	}

	def "Verify toString"(){
		expect:
		new LinkageValue(linkagevalue).toString() == "LinkageValue [010203040506070809]"
	}
}

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
package org.certificateservices.custom.c2x.ieee1609dot2.basic

import java.security.MessageDigest

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.common.BaseStructSpec;
import org.certificateservices.custom.c2x.its.crypto.DefaultCryptoManagerParams;

import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for LaId
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class LaIdSpec extends BaseStructSpec {
	
	byte[] laid  = Hex.decode("0102")
	


	
	def "Verify that LaId stores the data correctly"(){
		when:
		LaId h1 = new LaId(laid)
		then:
		h1.getLaId() == laid; // verify the methods returns the same data
		h1.getLaId().length == 2
		serializeToHex(h1) == "0102"
		
		when:
		LaId h2 = deserializeFromHex(new LaId(), "0102")
		then:
		h2.getLaId() == laid
	}

	def "Verify toString"(){
		expect:
		new LaId(laid).toString() == "LaId [0102]"
	}
}

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
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;

import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for LinkageSeed
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class LinkageSeedSpec extends BaseStructSpec {
	
	byte[] linkageSeed  = Hex.decode("000102030405060708090a0b0c0d0e0f")
	


	
	def "Verify that LinkageSeed stores the data correctly"(){
		when:
		LinkageSeed h1 = new LinkageSeed(linkageSeed)
		then:
		h1.getLinkageSeed() == linkageSeed; // verify the methods returns the same data
		h1.getLinkageSeed().length == 16
		serializeToHex(h1) == "000102030405060708090a0b0c0d0e0f"
		
		when:
		LinkageSeed h2 = deserializeFromHex(new LinkageSeed(), "000102030405060708090a0b0c0d0e0f")
		then:
		h2.getLinkageSeed() == linkageSeed
	}

	def "Verify toString"(){
		expect:
		new LinkageSeed(linkageSeed).toString() == "LinkageSeed [000102030405060708090a0b0c0d0e0f]"
	}
}

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
 * Test for all HashedIdX classes
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class AllHashedIdSpec extends BaseStructSpec {
	
	byte[] fullHashValue;
	
	def setup(){
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		md.update("Some Text to be Hashed".getBytes("UTF-8"))
		fullHashValue = md.digest()
		
	}

	
	def "Verify that HashedId3 only stores the 3 least significant bytes"(){
		when:
		HashedId3 h1 = new HashedId3(fullHashValue)
		then:
		h1.getHashedId() == h1.getData(); // verify the methods returns the same data
		h1.getHashedId().length == 3
		h1.getHashLength() == 3
		serializeToHex(h1) == "944d99"
		
		when:
		HashedId3 h2 = deserializeFromHex(new HashedId3(), "944d99")
		then:
		h2.getHashedId() == h1.getHashedId()
	}
	
	def "Verify that HashedId4 only stores the 4 least significant bytes"(){
		when:
		HashedId4 h1 = new HashedId4(fullHashValue)
		then:
		h1.getHashedId() == h1.getData(); // verify the methods returns the same data
		h1.getHashedId().length == 4
		h1.getHashLength() == 4
		serializeToHex(h1) == "f1944d99"
		
		when:
		HashedId4 h2 = deserializeFromHex(new HashedId4(), "f1944d99")
		then:
		h2.getHashedId() == h1.getHashedId()
	}
	
	def "Verify that HashedId8 only stores the 8 least significant bytes"(){
		when:
		HashedId8 h1 = new HashedId8(fullHashValue)
		then:
		h1.getHashedId() == h1.getData(); // verify the methods returns the same data
		h1.getHashedId().length == 8
		h1.getHashLength() == 8
		serializeToHex(h1) == "d778056af1944d99"
		
		when:
		HashedId8 h2 = deserializeFromHex(new HashedId8(), "d778056af1944d99")
		then:
		h2.getHashedId() == h1.getHashedId()
	}
	
	def "Verify that HashedId10 only stores the 10 least significant bytes"(){
		when:
		HashedId10 h1 = new HashedId10(fullHashValue)
		then:
		h1.getHashedId() == h1.getData(); // verify the methods returns the same data
		h1.getHashedId().length == 10
		h1.getHashLength() == 10
		serializeToHex(h1) == "9187d778056af1944d99"
		
		when:
		HashedId10 h2 = deserializeFromHex(new HashedId10(), "9187d778056af1944d99")
		then:
		h2.getHashedId() == h1.getHashedId()
	}
	
	def "Verify that HashedId32 only stores the 32 least significant bytes"(){
		when:
		HashedId32 h1 = new HashedId32(fullHashValue)
		then:
		h1.getHashedId() == h1.getData(); // verify the methods returns the same data
		h1.getHashedId().length == 32
		h1.getHashLength() == 32
		serializeToHex(h1) == "c32e18f74a92f3e413f2510eda33e23f29f3f25b8f7e9187d778056af1944d99"
		
		when:
		HashedId32 h2 = deserializeFromHex(new HashedId32(), "c32e18f74a92f3e413f2510eda33e23f29f3f25b8f7e9187d778056af1944d99")
		then:
		h2.getHashedId() == h1.getHashedId()
	}

	def "Verify toString"(){
		expect:
		new HashedId3(fullHashValue).toString() == "HashedId3 [944d99]"
		new HashedId4(fullHashValue).toString() == "HashedId4 [f1944d99]"
		new HashedId8(fullHashValue).toString() == "HashedId8 [d778056af1944d99]"
		new HashedId10(fullHashValue).toString() == "HashedId10 [9187d778056af1944d99]"
		new HashedId32(fullHashValue).toString() == "HashedId32 [c32e18f74a92f3e413f2510eda33e23f29f3f25b8f7e9187d778056af1944d99]"
	}
}

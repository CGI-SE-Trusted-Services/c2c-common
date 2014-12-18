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
package org.certificateservices.custom.c2x.its.datastructs.basic


import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.its.datastructs.BaseStructSpec;
import org.certificateservices.custom.c2x.its.datastructs.basic.HashedId3;
import org.certificateservices.custom.c2x.its.datastructs.basic.HashedId8;

import spock.lang.IgnoreRest;
import spock.lang.Specification;
import spock.lang.Unroll;

import static org.certificateservices.custom.c2x.its.datastructs.basic.EccPointType.*;

/**
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class HashedIdSpec extends BaseStructSpec {
	
	

	
	byte[] testValue = Hex.decode("998877665544332211");
	
	def "Verify the correct octet length of the HashedId3"(){
		expect:
		new String(Hex.encode(new HashedId3(testValue).hashedId)) == "332211"
		new String(Hex.encode(new HashedId8(testValue).hashedId)) == "8877665544332211"

	}
	
	def "Verify IllegalArgumentException is thrown if to small hash value is given."(){
		when:
		new String(Hex.encode(new HashedId8(Hex.decode("332211")).hashedId))
		then:
		thrown IllegalArgumentException
	}
	
	def "Verify serialization of a hash value"(){
		expect:
		serializeToHex(new HashedId3(testValue)) == "332211"
	}
	
	def "Verify deserialization of a hash value"(){
		when:
		HashedId3 h = deserializeFromHex(new HashedId3(),"332211")
		then:
		new String(Hex.encode(h.hashedId)) == "332211"
	}

	def "Verify hashCode and equals"(){
		setup:
		def t1  = new HashedId3(testValue);
		def t2  = new HashedId3(testValue);
		def t3  = new HashedId3(Hex.decode("998877665544332222"));
		expect:
		t1 == t2
		t1 != t3
		t1.hashCode() == t2.hashCode()
		t1.hashCode() != t3.hashCode()
	}
}

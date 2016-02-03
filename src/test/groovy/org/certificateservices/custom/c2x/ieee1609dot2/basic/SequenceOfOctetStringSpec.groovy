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

import org.certificateservices.custom.c2x.asn1.coer.COEROctetStream;
import org.certificateservices.custom.c2x.asn1.coer.COERSequenceOf
import org.certificateservices.custom.c2x.common.BaseStructSpec;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.IdentifiedRegion.IdentifiedRegionChoices;

import spock.lang.IgnoreRest;
import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for all SequenceOfOctedString class
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class SequenceOfOctetStringSpec extends BaseStructSpec {

	COEROctetStream s1 = new COEROctetStream("test".getBytes())
	COEROctetStream s2 = new COEROctetStream("test2".getBytes())
	
	
	def "Verify that SequenceOfOctetString is initialized properly"(){
		when:
		def u1 = deserializeFromHex(new SequenceOfOctetString(),"01020474657374057465737432")
		then:
		u1.getSequenceValues()[0].getData() == "test".getBytes()
		u1.getSequenceValues()[1].getData()  == "test2".getBytes()
		when:
		def u2 = new SequenceOfOctetString([s1,s2] as COEROctetStream[])
		then:
		u2.getSequenceValues()[0].getData() == "test".getBytes()
		u2.getSequenceValues()[1].getData()  == "test2".getBytes()
		
		
		when:
		def u3 = new SequenceOfOctetString([s1,s2])
		then:
		u3.getSequenceValues()[0].getData() == "test".getBytes()
		u3.getSequenceValues()[1].getData()  == "test2".getBytes()
	}
	
	
	def "Verify toString"(){
		expect:
		new SequenceOfOctetString([s1,s2]).toString() == "SequenceOfOctetString [COEROctetStream [data=74657374],COEROctetStream [data=7465737432]]"
		new SequenceOfOctetString().toString() == "SequenceOfOctetString []"
		new SequenceOfOctetString([s1]).toString() == "SequenceOfOctetString [COEROctetStream [data=74657374]]"
		
	
	}
	
	


}

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

import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;

import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for Opaque
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class HostnameSpec extends Specification {

	
	def "Verify that Hostname has size boundraries 0 to 255"(){
		when:
		def h = new Hostname()
		
		then:
		h.getLowerBound() == 0
		h.getUpperBound() == 255
		
		when:
		def h2 = new Hostname("test")
		then:
		h2.getLowerBound() == 0
		h2.getUpperBound() == 255
		h2.getUTF8String() == "test"
		
	}
	
	def "Verify toString"(){
		expect:
		new Hostname("test").toString() == "Hostname [test]"
	}
	

}

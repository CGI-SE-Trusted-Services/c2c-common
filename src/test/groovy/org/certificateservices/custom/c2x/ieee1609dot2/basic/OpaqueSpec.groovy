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
class OpaqueSpec extends Specification {

	
	def "Verify that Opaque has no size boundraries"(){
		when:
		def o = new Opaque()
		
		then:
		o.getLowerBound() == null
		o.getUpperBound() == null
		
	}
	
	def "Verify toString"(){
		expect:
		new Opaque("Test".getBytes("UTF-8")).toString() == "Opaque [data=54657374]"
	}
	

}

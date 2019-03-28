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
package org.certificateservices.custom.c2x.asn1.coer


import org.certificateservices.custom.c2x.common.BaseStructSpec

/**
 * Unit tests for COERIA5String
 *
 * @author Philip Vendil, p.vendil@cgi.com
 */
class COERIA5StringSpec extends BaseStructSpec {

	def "Verify that constructor and getter"(){
		expect:
		new COERIA5String(4,5).getLowerBound() == 4
		new COERIA5String(4,5).getUpperBound() == 5
		new COERIA5String("a").getAI5String() == "a"
		new COERIA5String("a",1,5).getLowerBound() == 1
		new COERIA5String("a",1,5).getUpperBound() == 5
		new COERIA5String("ab",1,5).getAI5String() == "ab"
	}

	def "Verify that constructor throws IllegalArgumentException if IA5 string contains invalid values"(){
		when:
		new COERIA5String("ä")
		then:
		def e = thrown IllegalArgumentException
		e.message == "Invalid IA5String characters in string: ä"
		when:
		new COERIA5String("ä",1,5)
		then:
		e = thrown IllegalArgumentException
		e.message == "Invalid IA5String characters in string: ä"
	}
		
	def "Verify toString"(){
		expect:
		new COERIA5String("ab").toString() == "COERIA5String [IA5String=ab]"
	}

}

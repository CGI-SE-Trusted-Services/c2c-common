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


import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.common.BaseStructSpec

import spock.lang.Specification
import spock.lang.Unroll;


class COERUTF8StringSpec extends BaseStructSpec {
	


	def "Verify that constuctor and getter"(){
		expect:
		new COERUTF8String(4,5).getLowerBound() == 4
		new COERUTF8String(4,5).getUpperBound() == 5
		new COERUTF8String("a").getUTF8String() == "a"
		new COERUTF8String("a",1,5).getLowerBound() == 1
		new COERUTF8String("a",1,5).getUpperBound() == 5
		new COERUTF8String("ab",1,5).getUTF8String() == "ab"
	}
		
	def "Verify toString"(){
		expect:
		new COERUTF8String("ab").toString() == "COERUTF8String [UTF8String=ab]"
	}
	

}

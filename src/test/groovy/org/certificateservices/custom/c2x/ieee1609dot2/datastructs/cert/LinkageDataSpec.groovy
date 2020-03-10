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
package org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert


import org.certificateservices.custom.c2x.common.BaseStructSpec
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.GroupLinkageValue
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.IValue
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.LinkageValue
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.LinkageData

/**
 * Test for LinkageData
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */

class LinkageDataSpec extends BaseStructSpec {

	IValue c = new IValue(5);
	LinkageValue lv = new LinkageValue("012345678".bytes)
	GroupLinkageValue gvl = new GroupLinkageValue("1234".bytes,"012345678".bytes)
	
	def "Verify that constructor and getters are correct and it is correctly encoded"(){
		when:
		LinkageData ld1 = new LinkageData(c,lv,gvl)
		then:
		serializeToHex(ld1) == "80000530313233343536373831323334303132333435363738"
		when:
		LinkageData ld2 = deserializeFromHex(new LinkageData(), "80000530313233343536373831323334303132333435363738")
		then:
		ld2.getICert() == c
		ld2.getLinkageValue() == lv
		ld2.getGroupLinkageValue() == gvl
		when:
		LinkageData ld3 = new LinkageData(c,lv,null)
		then:
		serializeToHex(ld3) == "000005303132333435363738"
		when:
		LinkageData ld4 = deserializeFromHex(new LinkageData(), "000005303132333435363738")
		then:
		ld4.getICert() == c
		ld4.getLinkageValue() == lv
		ld4.getGroupLinkageValue() == null
		
	}
	
	def "Verify that IOException is thrown when encoding if not all fields are set"(){
		when:
		new LinkageData(c,null,null)
		then:
		thrown IOException
		when:
		new LinkageData(null,lv,null)
		then:
		thrown IOException
	} 
	

	def "Verify toString"(){
		expect:
		new LinkageData(c,lv,gvl).toString() == "LinkageData [iCert=[5], linkage-value=[303132333435363738], group-linkage-value=[jvalue=31323334, value=303132333435363738]]"
		new LinkageData(c,lv,null).toString() == "LinkageData [iCert=[5], linkage-value=[303132333435363738], group-linkage-value=NULL]"
	}
	

}

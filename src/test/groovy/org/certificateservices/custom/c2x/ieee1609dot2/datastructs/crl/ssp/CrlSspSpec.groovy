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
package org.certificateservices.custom.c2x.ieee1609dot2.datastructs.crl.ssp

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.asn1.coer.COEREncodeHelper;
import org.certificateservices.custom.c2x.common.BaseStructSpec;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.CrlSeries;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.LaId;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.LinkageSeed;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Opaque
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Duration.DurationChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccP256CurvePoint.EccP256CurvePointChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.SubjectPermissions.SubjectPermissionsChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.crl.ssp.CracaType;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.crl.ssp.CrlSsp;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.crl.ssp.PermissibleCrls;
import org.junit.Ignore;

import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for CrlSsp
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */

class CrlSspSpec extends BaseStructSpec {

	
	PermissibleCrls crls = new PermissibleCrls([new CrlSeries(7), new CrlSeries(8)])
    
	def "Verify that constructor and getters are correct and it is correctly encoded"(){
		when:
		CrlSsp cs1 = new CrlSsp(CracaType.issuerIsCraca, crls)
		then:
		cs1.hasExtension
		serializeToHex(cs1) == "000101010200070008"
		when:
		CrlSsp cs2 = deserializeFromHex(new CrlSsp(), "000101010200070008")
		then:
		cs2.hasExtension
		cs2.getVersion() == CrlSsp.DEFAULT_VERSION
		cs2.getAssociatedCraca() == CracaType.issuerIsCraca
		cs2.getCrls() == crls
		
	}
	
	def "Verify that IllegalArgumentException is thrown when encoding if not all fields are set"(){
		when:
		new CrlSsp(null, crls)
		then:
		thrown IllegalArgumentException
		when:
		new CrlSsp(CracaType.issuerIsCraca, null)
		then:
		thrown IllegalArgumentException
	} 
	

	def "Verify toString"(){
		expect:
		new CrlSsp(CracaType.issuerIsCraca, crls).toString() == """CrlSsp [version=1,  associatedCraca=issuerIsCraca, crls=[[7],[8]]]"""
	}
	

}

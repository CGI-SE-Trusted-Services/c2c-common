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

import org.certificateservices.custom.c2x.asn1.coer.COEREncodeHelper;
import org.certificateservices.custom.c2x.common.BaseStructSpec;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Duration.DurationChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccP256CurvePoint.EccP256CurvePointChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.SubjectPermissions.SubjectPermissionsChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.EndEntityType;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.PsidGroupPermissions;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.SubjectPermissions;
import org.junit.Ignore;

import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for PsidGroupPermissions
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */

class PsidGroupPermissionsSpec extends BaseStructSpec {

	SubjectPermissions appPerms = new SubjectPermissions(SubjectPermissionsChoices.all, null)
	EndEntityType eeType = new EndEntityType(false, true)
	
	def "Verify that constructor and getters are correct and it is correctly encoded"(){
		when:
		PsidGroupPermissions perm1 = new PsidGroupPermissions(appPerms,null,null,eeType)
		then:
		serializeToHex(perm1) == "008140"
		when:
		PsidGroupPermissions perm2 = deserializeFromHex(new PsidGroupPermissions(), "008140")
		then:
		perm2.getAppPermissions() == appPerms
		perm2.getMinChainDepth() == 1
		perm2.getChainDepthRange() == 0
		perm2.getEEType() == eeType
		when:
		PsidGroupPermissions perm3 = new PsidGroupPermissions(appPerms,2,4,eeType)
		then:
		serializeToHex(perm3) == "c0810102010440"
		when:
		PsidGroupPermissions perm4 = deserializeFromHex(new PsidGroupPermissions(), "c0810102010440")
		then:
		perm4.getAppPermissions() == appPerms
		perm4.getMinChainDepth() == 2
		perm4.getChainDepthRange() == 4
		perm4.getEEType() == eeType
		
	}
	
	def "Verify that IllegalArgumentException is thrown when encoding if not all fields are set"(){
		when:
		new PsidGroupPermissions(appPerms,null,null,null)
		then:
		thrown IllegalArgumentException
		when:
		new PsidGroupPermissions(null,null,null,eeType)
		then:
		thrown IllegalArgumentException
	} 
	

	def "Verify toString"(){
		expect:
		new PsidGroupPermissions(appPerms,2,4,eeType).toString() == "PsidGroupPermissions [appPermissions=[all], minChainDepth=2, chainDepthRange=4, eeType=[app=false, enroll=true]]"
	}
	

}

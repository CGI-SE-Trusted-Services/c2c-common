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
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.EndEntityType
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.PsidGroupPermissions
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.SubjectPermissions
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.SubjectPermissions.SubjectPermissionsChoices

/**
 * Test for PsidGroupPermissions
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */

class PsidGroupPermissionsSpec extends BaseStructSpec {

	SubjectPermissions subjectPerms = new SubjectPermissions(SubjectPermissionsChoices.all, null)
	EndEntityType eeType = new EndEntityType(false, true)
	
	def "Verify that constructor and getters are correct and it is correctly encoded"(){
		when:
		PsidGroupPermissions perm1 = new PsidGroupPermissions(subjectPerms,null,null,eeType)
		then:
		serializeToHex(perm1) == "208140"
		when:
		PsidGroupPermissions perm2 = deserializeFromHex(new PsidGroupPermissions(), "208140")
		then:
		perm2.getSubjectPermissions() == subjectPerms
		perm2.getMinChainDepth() == 1
		perm2.getChainDepthRange() == 0
		perm2.getEEType() == eeType
		when:
		PsidGroupPermissions perm3 = new PsidGroupPermissions(subjectPerms,2,4,eeType)
		then:
		serializeToHex(perm3) == "e0810102010440"
		when:
		PsidGroupPermissions perm4 = deserializeFromHex(new PsidGroupPermissions(), "e0810102010440")
		then:
		perm4.getSubjectPermissions() == subjectPerms
		perm4.getMinChainDepth() == 2
		perm4.getChainDepthRange() == 4
		perm4.getEEType() == eeType
		
	}
	
	def "Verify that BadArgumentException is thrown when encoding if not all fields are set"(){
		when:
		new PsidGroupPermissions(null,null,null,null)
		then:
		thrown IOException
	}
	

	def "Verify toString"(){
		expect:
		new PsidGroupPermissions(subjectPerms,2,4,eeType).toString() == "PsidGroupPermissions [subjectPermissions=[all], minChainDepth=2, chainDepthRange=4, eeType=[app=false, enroll=true]]"
	}
	

}

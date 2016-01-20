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
package org.certificateservices.custom.c2x.ieee1609dot2.secureddata

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.asn1.coer.COEREncodeHelper;
import org.certificateservices.custom.c2x.common.BaseStructSpec;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Duration.DurationChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.EccP256CurvePoint.EccP256CurvePointChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.CrlSeries
import org.certificateservices.custom.c2x.ieee1609dot2.basic.HashedId3;
import org.certificateservices.custom.c2x.ieee1609dot2.cert.SubjectPermissions.SubjectPermissionsChoices;
import org.certificateservices.custom.c2x.its.crypto.DefaultCryptoManagerParams;
import org.junit.Ignore;

import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for MissingCrlIdentifier
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */

class MissingCrlIdentifierSpec extends BaseStructSpec {

	HashedId3 cracaid = new HashedId3(Hex.decode("010203040506070809101112"))
	CrlSeries crlSeries =new CrlSeries(100)
	
	def "Verify that constructor and getters are correct and it is correctly encoded"(){
		when:
		MissingCrlIdentifier mci1 = new MissingCrlIdentifier(cracaid,crlSeries)
		then:
		mci1.hasExtension
		serializeToHex(mci1) == "001011120064"
		when:
		MissingCrlIdentifier mci2 = deserializeFromHex(new MissingCrlIdentifier(), "001011120064")
		then:
		mci2.hasExtension
		mci2.getCracaid() == cracaid
		mci2.getCrlSeries() == crlSeries
	
		
	}
	
	def "Verify that IllegalArgumentException is thrown when encoding if not all fields are set"(){
		when:
		new MissingCrlIdentifier(null, crlSeries)
		then:
		thrown IllegalArgumentException
		when:
		new MissingCrlIdentifier(cracaid,null)
		then:
		thrown IllegalArgumentException
	} 
	

	def "Verify toString"(){
		expect:
		new MissingCrlIdentifier(cracaid,crlSeries).toString() == "MissingCrlIdentifier [cracaid=[101112], crlSeries=[100]]"
	}
	

}

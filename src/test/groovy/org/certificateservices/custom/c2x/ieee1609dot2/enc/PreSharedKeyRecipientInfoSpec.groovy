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
package org.certificateservices.custom.c2x.ieee1609dot2.enc

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.asn1.coer.COEREncodeHelper;
import org.certificateservices.custom.c2x.common.BaseStructSpec;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.EccP256CurvePoint;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.EciesP256EncryptedKey;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.HashedId8
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Duration.DurationChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.EccP256CurvePoint.EccP256CurvePointChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.cert.SubjectPermissions.SubjectPermissionsChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.enc.EncryptedDataEncryptionKey.EncryptedDataEncryptionKeyChoices;
import org.junit.Ignore;

import spock.lang.Shared;
import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for PreSharedKeyRecipientInfo
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */

class PreSharedKeyRecipientInfoSpec extends BaseStructSpec {
	

	byte[] recepientId = Hex.decode("01020304050607080910")
	
	
	def "Verify that constructor and getters are correct and it is correctly encoded"(){
		when:
		PreSharedKeyRecipientInfo ri1 = new PreSharedKeyRecipientInfo(recepientId)
		then:
		serializeToHex(ri1) == "0304050607080910"
		when:
		PreSharedKeyRecipientInfo ri2 = deserializeFromHex(new PreSharedKeyRecipientInfo(), "0304050607080910")
		then:
		ri2.getHashedId() == Hex.decode("0304050607080910")
	
	}
	

	

	def "Verify toString"(){
		expect:
		new PreSharedKeyRecipientInfo(recepientId).toString() == "PreSharedKeyRecipientInfo [0304050607080910]"
	}
	

}

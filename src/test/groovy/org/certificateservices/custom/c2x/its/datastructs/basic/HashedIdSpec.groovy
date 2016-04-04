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
package org.certificateservices.custom.c2x.its.datastructs.basic


import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.common.BaseStructSpec;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManager
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams
import org.certificateservices.custom.c2x.its.crypto.ITSCryptoManager;
import org.certificateservices.custom.c2x.its.datastructs.basic.HashedId3;
import org.certificateservices.custom.c2x.its.datastructs.basic.HashedId8;
import org.certificateservices.custom.c2x.its.datastructs.cert.Certificate

import spock.lang.IgnoreRest;
import spock.lang.Specification;
import spock.lang.Unroll;
import static org.certificateservices.custom.c2x.its.datastructs.basic.EccPointType.*;

/**
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class HashedIdSpec extends BaseStructSpec {
	
	

	
	byte[] testValue = Hex.decode("998877665544332211");
	
	def "Verify the correct octet length of the HashedId3"(){
		expect:
		new String(Hex.encode(new HashedId3(testValue).hashedId)) == "332211"
		new String(Hex.encode(new HashedId8(testValue).hashedId)) == "8877665544332211"

	}
	
	def "Verify IllegalArgumentException is thrown if to small hash value is given."(){
		when:
		new String(Hex.encode(new HashedId8(Hex.decode("332211")).hashedId))
		then:
		thrown IllegalArgumentException
	}
	
	def "Verify serialization of a hash value"(){
		expect:
		serializeToHex(new HashedId3(testValue)) == "332211"
	}
	
	def "Verify deserialization of a hash value"(){
		when:
		HashedId3 h = deserializeFromHex(new HashedId3(),"332211")
		then:
		new String(Hex.encode(h.hashedId)) == "332211"
	}

	def "Verify hashCode and equals"(){
		setup:
		def t1  = new HashedId3(testValue);
		def t2  = new HashedId3(testValue);
		def t3  = new HashedId3(Hex.decode("998877665544332222"));
		expect:
		t1 == t2
		t1 != t3
		t1.hashCode() == t2.hashCode()
		t1.hashCode() != t3.hashCode()
	}
	
	def "Verify that certificate signature R point normalises signature r value to X only"(){
		setup:
		ITSCryptoManager cm = new DefaultCryptoManager();
		cm.setupAndConnect(new DefaultCryptoManagerParams("BC"))

		expect:
		new HashedId3(getSignatureWithUncompressedR(),cm) == new HashedId3(getSignatureWithXOnlyR(),cm)
		new HashedId8(getSignatureWithUncompressedR(),cm) == new HashedId8(getSignatureWithXOnlyR(),cm)
	}
	
	
	static def byte[] certXOnlyData = Hex.decode("0200040049000004C75A096E2C522BA46E81B1DE939DBB2253AEA3A3311F2FCEC5B770F08289F314BAD63CE192DD0221DDA60FA6B68942B1CB4F2018519EE13F0ED0B9DCD6CAA7C702C0200224250B0114B12B0316925E8403000000324FA8D25CA88619E29CE89DBF410F6DF555498850341E3791552B473B54168409FEF44BC7910C5D61D7D138B710D2693B37980B287077A70E01A341FD6A2599")
	static def Certificate getSignatureWithUncompressedR(){
		
		
		
		Certificate c = new Certificate(certXOnlyData);
		
		BigInteger x = c.getSignature().signatureValue.getR().x
		c.getSignature().signatureValue.setR(new EccPoint(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, EccPointType.uncompressed, x, new BigInteger(123L)));
		
		return c
	}
	
	static def Certificate getSignatureWithXOnlyR(){
		return new Certificate(certXOnlyData)
	}
}

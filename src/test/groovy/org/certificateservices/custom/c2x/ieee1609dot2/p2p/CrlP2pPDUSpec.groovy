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
package org.certificateservices.custom.c2x.ieee1609dot2.p2p

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.asn1.coer.COEREncodeHelper;
import org.certificateservices.custom.c2x.asn1.coer.COERNull
import org.certificateservices.custom.c2x.common.BaseStructSpec;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Duration.DurationChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.EccP256CurvePoint.EccP256CurvePointChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.CrlSeries
import org.certificateservices.custom.c2x.ieee1609dot2.basic.EccP256CurvePoint;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.EcdsaP256Signature
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Elevation
import org.certificateservices.custom.c2x.ieee1609dot2.basic.EncryptionKey;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.HashAlgorithm;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.HashedId3;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.HashedId8;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Latitude
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Longitude
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Opaque;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Psid
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Signature;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.SymmetricEncryptionKey;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.SymmetricEncryptionKey.SymmetricEncryptionKeyChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.ThreeDLocation;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Time64;
import org.certificateservices.custom.c2x.ieee1609dot2.basic.Signature.SignatureChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.cert.SubjectPermissions.SubjectPermissionsChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.enc.AesCcmCiphertext
import org.certificateservices.custom.c2x.ieee1609dot2.enc.EncryptedData;
import org.certificateservices.custom.c2x.ieee1609dot2.enc.PreSharedKeyRecipientInfo;
import org.certificateservices.custom.c2x.ieee1609dot2.enc.RecipientInfo;
import org.certificateservices.custom.c2x.ieee1609dot2.enc.SequenceOfRecipientInfo;
import org.certificateservices.custom.c2x.ieee1609dot2.enc.SymmetricCiphertext;
import org.certificateservices.custom.c2x.ieee1609dot2.secureddata.HashedData.HashedDataChoices;
import org.certificateservices.custom.c2x.ieee1609dot2.secureddata.Ieee1609Dot2Content.Ieee1609Dot2ContentChoices;
import org.junit.Ignore;

import spock.lang.IgnoreRest;
import spock.lang.Shared;
import spock.lang.Specification;
import spock.lang.Unroll;

/**
 * Test for CrlP2pPDU
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */

class CrlP2pPDUSpec extends BaseStructSpec {

	def "Verify constructor"(){
		expect:
		new CrlP2pPDU() instanceof COERNull
	}
	
	def "Verify toString()"(){
		expect:
		new CrlP2pPDU().toString() == "CrlP2pPDU [NULL]"
	}

}

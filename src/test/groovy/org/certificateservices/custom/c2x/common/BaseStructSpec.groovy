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
package org.certificateservices.custom.c2x.common

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.common.Encodable;
import org.certificateservices.custom.c2x.its.datastructs.basic.EccPoint;
import org.certificateservices.custom.c2x.its.datastructs.basic.EccPointType;
import org.certificateservices.custom.c2x.its.datastructs.basic.EcdsaSignature
import org.certificateservices.custom.c2x.its.datastructs.basic.IntX;
import org.certificateservices.custom.c2x.its.datastructs.basic.PublicKey;
import org.certificateservices.custom.c2x.its.datastructs.basic.PublicKeyAlgorithm;
import org.certificateservices.custom.c2x.its.datastructs.basic.Signature;
import org.certificateservices.custom.c2x.its.datastructs.basic.SignerInfo;
import org.certificateservices.custom.c2x.its.datastructs.basic.Time32;
import org.certificateservices.custom.c2x.its.datastructs.cert.Certificate
import org.certificateservices.custom.c2x.its.datastructs.cert.ItsAidSsp
import org.certificateservices.custom.c2x.its.datastructs.cert.SubjectAssurance
import org.certificateservices.custom.c2x.its.datastructs.cert.SubjectAttribute;
import org.certificateservices.custom.c2x.its.datastructs.cert.SubjectAttributeType;
import org.certificateservices.custom.c2x.its.datastructs.cert.SubjectInfo;
import org.certificateservices.custom.c2x.its.datastructs.cert.SubjectType
import org.certificateservices.custom.c2x.its.datastructs.cert.ValidityRestriction;

import spock.lang.Specification

/**
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
abstract class BaseStructSpec extends Specification {
	
	String serializeToHex(Encodable o){
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		DataOutputStream dos = new DataOutputStream(baos);
		
		o.encode(dos);
		dos.close();
		
		
		return new String(Hex.encode(baos.toByteArray()));
	}
	
	Encodable deserializeFromHex(Encodable o, String hexData){
		ByteArrayInputStream bais = new ByteArrayInputStream(Hex.decode(hexData));
		DataInputStream dis = new DataInputStream(bais);
		
		o.decode(dis);
		dis.close();	
		
		return o;				
	}
	
	// TODO Refactor everything

	// TODO
	Certificate genCertificate(int certVersion, SubjectType type, String subjectName, Certificate cACertificate=null){
		
		SignerInfo si = new SignerInfo();
		if(cACertificate != null){
			si = new SignerInfo(cACertificate)
		}
		
		PublicKey publicKey1 = new PublicKey(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256,new EccPoint(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, EccPointType.x_coordinate_only, new BigInteger(1)))
		PublicKey publicKey2 = new PublicKey(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256,new EccPoint(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, EccPointType.x_coordinate_only, new BigInteger(2)))
		
		SubjectAttribute sav = new SubjectAttribute(SubjectAttributeType.verification_key, publicKey1);
		SubjectAttribute sae = new SubjectAttribute(new SubjectAssurance(4, 2));
		SubjectAttribute sal = new SubjectAttribute(SubjectAttributeType.its_aid_ssp_list, [new ItsAidSsp(new IntX(1L), new byte[2])]);
		
		ValidityRestriction vr1 = new ValidityRestriction(new Time32(certVersion,new Date(1416581892590L)));
		ValidityRestriction vr2 = new ValidityRestriction(new Time32(certVersion,new Date(1416581882582L)),new Time32(certVersion,new Date(1416581892590L)));
		
		SubjectInfo subjectInfo = new SubjectInfo(type, subjectName.getBytes());
		
		Signature sig = new Signature(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, new EcdsaSignature(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, new EccPoint(PublicKeyAlgorithm.ecdsa_nistp256_with_sha256, EccPointType.x_coordinate_only, new BigInteger(1)), new byte[32]))
		
		return new Certificate(certVersion, [si], subjectInfo, [sav,sae,sal],[vr1,vr2],sig);
	}

}

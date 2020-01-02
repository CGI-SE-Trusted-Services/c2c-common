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

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.spec.ECParameterSpec
import org.bouncycastle.jce.spec.ECPrivateKeySpec
import org.bouncycastle.math.ec.ECPoint
import org.bouncycastle.util.encoders.Hex
import spock.lang.Shared
import spock.lang.Specification

import java.security.KeyFactory
import java.security.KeyPair
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECPublicKeySpec

/**
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
abstract class BaseStructSpec extends Specification {

	@Shared TimeZone localTimeZone

	def setupSpec(){
		localTimeZone = TimeZone.getDefault()
		TimeZone.setDefault(TimeZone.getTimeZone("Europe/Stockholm"))

	}

	def cleanupSpec(){
		TimeZone.setDefault(localTimeZone)

	}
	
	String serializeToHex(Encodable o){
		ByteArrayOutputStream baos = new ByteArrayOutputStream()
		DataOutputStream dos = new DataOutputStream(baos)
		
		o.encode(dos)
		dos.close()
		
		
		return new String(Hex.encode(baos.toByteArray()))
	}
	
	Encodable deserializeFromHex(Encodable o, String hexData){
		ByteArrayInputStream bais = new ByteArrayInputStream(Hex.decode(hexData))
		DataInputStream dis = new DataInputStream(bais)
		
		o.decode(dis)
		dis.close()
		
		return o
	}

	String normalizeHex(String hexData){
		return hexData.replaceAll("\n","").replaceAll(" ","").toLowerCase()
	}

	private String staticNistP256KeyPair_d = "9a73bbb5c19853ba581c71a7b7e40e14b65a5b4692ec37720700d474e3c45e4b"

	KeyPair getStaticNistP256KeyPair(){
		ECParameterSpec ecNistP256Spec = ECNamedCurveTable.getParameterSpec("P-256")
		ECPrivateKeySpec recipientPrivateKeySpec = new ECPrivateKeySpec(new BigInteger(staticNistP256KeyPair_d,16), ecNistP256Spec)
		KeyFactory kf = KeyFactory.getInstance("EC", "BC")
		BCECPrivateKey privateKey = (BCECPrivateKey) kf.generatePrivate(recipientPrivateKeySpec)
		ECPoint Q = ecNistP256Spec.getG().multiply(((org.bouncycastle.jce.interfaces.ECPrivateKey) privateKey).getD())
		org.bouncycastle.jce.spec.ECPublicKeySpec pubSpec = new org.bouncycastle.jce.spec.ECPublicKeySpec(Q, privateKey.getParameters())
		ECPublicKey publicKey = (ECPublicKey) kf.generatePublic(pubSpec)
		return new KeyPair(publicKey,privateKey)
	}

}

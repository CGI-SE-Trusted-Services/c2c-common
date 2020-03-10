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
package org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic;

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.asn1.coer.COEROctetStream;
import org.certificateservices.custom.c2x.asn1.coer.COERSequence;

import java.io.IOException;

/**
 * This data structure is used to transfer a 16-byte symmetric key encrypted using ECIES as specified in IEEE Std 1363a-2004. 
 * The type contains the following fields:
 * <li>v is the sender’s ephemeral public key, which is the output V from encryption as specified in 5.3.5.
 * <li>c is the encrypted symmetric key, which is the output C from encryption as specified in 5.3.5. The algorithm for the symmetric key is 
 * identified by the CHOICE indicated in the following SymmetricCiphertext.
 * <li>t is the authentication tag, which is the output tag from encryption as specified in 5.3.5.
 * 
 * Encryption and decryption are carried out as specified in 5.3.5.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */

public class EciesP256EncryptedKey extends COERSequence {
	
	private static final int OCTETSTRING_SIZE = 16;
	
	private static final long serialVersionUID = 1L;
	
	private static final int V = 0;
	private static final int C = 1;
	private static final int T = 2;

	/**
	 * Constructor used when decoding
	 */
	public EciesP256EncryptedKey(){
		super(false,3);
		init();
	}
	
	/**
	 * Constructor used when encoding
	 */
	public EciesP256EncryptedKey(EccP256CurvePoint v, byte[] c, byte[] t) throws IOException {
		super(false,3);
		init();
		if(c == null){
			throw new IOException("Invalid argument, c cannot be null for EciesP256EncryptedKey");
		}
		if(t == null){
			throw new IOException("Invalid argument, t cannot be null for EciesP256EncryptedKey");
		}
		set(V,v);
		set(C, new COEROctetStream(c, OCTETSTRING_SIZE, OCTETSTRING_SIZE));
		set(T, new COEROctetStream(t, OCTETSTRING_SIZE, OCTETSTRING_SIZE));
	}

	/**
	 * 
	 * @return v value
	 */
	public EccP256CurvePoint getV(){
		return (EccP256CurvePoint) get(V);
	}
	
	/**
	 * 
	 * @return the 16 byte c value
	 */
	public byte[] getC(){
		return ((COEROctetStream) get(C)).getData();
	}
	
	/**
	 * 
	 * @return the 16 byte t value
	 */
	public byte[] getT(){
		return ((COEROctetStream) get(T)).getData();
	}
	
	private void init(){
		addField(V, false, new EccP256CurvePoint(), null);
		addField(C, false, new COEROctetStream(OCTETSTRING_SIZE, OCTETSTRING_SIZE), null);
		addField(T, false, new COEROctetStream(OCTETSTRING_SIZE, OCTETSTRING_SIZE), null);
	}
	
	@Override
	public String toString() {
		return "EciesP256EncryptedKey [v=" + getV().toString().replaceAll("EccP256CurvePoint ", "") + ", s=" + new String(Hex.encode(getC())) + ", t=" + new String(Hex.encode(getT()))+ "]";
	}
	
}

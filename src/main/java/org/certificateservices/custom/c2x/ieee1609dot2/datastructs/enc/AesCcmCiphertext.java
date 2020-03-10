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
package org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc;

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.asn1.coer.COEROctetStream;
import org.certificateservices.custom.c2x.asn1.coer.COERSequence;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Opaque;

import java.io.IOException;

/**
 * This data structure encapsulates an encrypted ciphertext for the AES-CCM symmetric algorithm. 
 * It contains the following fields:
 * <ul>
 * <li>nonce contains the nonce N as specified in 5.3.8.</li>
 * <li>ccmCiphertext contains the ciphertext C as specified in 5.3.8.</li>
 * </ul>
 * <p>
 * The ciphertext is 16 bytes longer than the corresponding plaintext.
 * </p>
 * <p>
 * The plaintext resulting from a correct decryption of the ciphertext is a COER-encoded Ieee1609Dot2Data structure.
 * </p>
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class AesCcmCiphertext extends COERSequence {
	

	private static final long serialVersionUID = 1L;
	
	private static final int NOUNCE = 0;
	private static final int CCMCIPHERTEXT = 1;

	/**
	 * Constructor used when decoding
	 */
	public AesCcmCiphertext(){
		super(false,2);
		init();
	}
	
	/**
	 * Constructor used when encoding
	 */
	public AesCcmCiphertext(byte[] nounce, byte[] ccmCipherText) throws IOException{
		super(false,2);
		init();
		if(nounce == null){
			throw new IOException("Error nounce value cannot be null in AesCcmCiphertext");
		}
		if(ccmCipherText == null){
			throw new IOException("Error ccmCipherText value cannot be null in AesCcmCiphertext");
		}
		set(NOUNCE, new COEROctetStream(nounce,12,12));
		set(CCMCIPHERTEXT, new Opaque(ccmCipherText));
	
	}

	/**
	 * 
	 * @return nounce
	 */
	public byte[] getNounce(){
		return ((COEROctetStream) get(NOUNCE)).getData();
	}
	
	/**
	 * 
	 * @return ccmCipherText
	 */
	public byte[] getCcmCipherText(){
		return ((Opaque) get(CCMCIPHERTEXT)).getData();
	}
	

	
	private void init(){
		addField(NOUNCE, false, new COEROctetStream(12,12), null);
		addField(CCMCIPHERTEXT, false, new Opaque(), null);
	}
	
	@Override
	public String toString() {
		return "AesCcmCiphertext [nounce=" + new String(Hex.encode(getNounce())) + ", ccmCipherText=" + new String(Hex.encode(getCcmCipherText())) + "]";
	}
	
}

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

import org.certificateservices.custom.c2x.asn1.coer.COEREnumeration;
import org.certificateservices.custom.c2x.asn1.coer.COERSequence;

import java.io.IOException;

/**
 * This structure specifies a public encryption key and the associated symmetric algorithm which is 
 * used for bulk data encryption when encrypting for that public key.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class PublicEncryptionKey extends COERSequence {
	
	
	private static final long serialVersionUID = 1L;
	
	private static final int SUPPORTEDSYMMALG = 0;
	private static final int PUBLICKEY = 1;

	/**
	 * Constructor used when decoding
	 */
	public PublicEncryptionKey(){
		super(false,2);
		init();
	}
	
	/**
	 * Constructor used when encoding
	 */
	public PublicEncryptionKey(SymmAlgorithm symmAlgorithm, BasePublicEncryptionKey publicKey) throws IOException {
		super(false,2);
		init();
		if(symmAlgorithm == null){
			throw new IOException("Illegal argument: symmAlgorithm cannot be null for PublicEncryptionKey");
		}
		set(SUPPORTEDSYMMALG, new COEREnumeration(symmAlgorithm));
		set(PUBLICKEY, publicKey);
	}



	/**
	 * 
	 * @return the supported SymmAlgorithm
	 */
	public SymmAlgorithm getSupportedSymmAlg(){
		return (SymmAlgorithm) ((COEREnumeration) get(SUPPORTEDSYMMALG)).getValue();
	}
	
	/**
	 * 
	 * @return the public key
	 */
	public BasePublicEncryptionKey getPublicKey(){
		return (BasePublicEncryptionKey) get(PUBLICKEY);
	}
	

	private void init(){
		addField(SUPPORTEDSYMMALG, false, new COEREnumeration(SymmAlgorithm.class), null);
		addField(PUBLICKEY, false, new BasePublicEncryptionKey(), null);
	}
	
	@Override
	public String toString() {
		return "PublicEncryptionKey [supportedSymmAlg=" + getSupportedSymmAlg() + ", publicKey=" + getPublicKey().toString().replace("BasePublicEncryptionKey ","") + "]";
	}
	

	
}

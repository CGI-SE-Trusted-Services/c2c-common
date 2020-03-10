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
package org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes;

import org.certificateservices.custom.c2x.asn1.coer.COERSequence;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.*;

import java.io.IOException;

/**
 * Class representing PublicKeys defined in ETSI TS 102 941 Base Types.
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class PublicKeys extends COERSequence {

	private static final long serialVersionUID = 1L;

	private static final int VERIFICATIONKEY = 0;
	private static final int ENCRYPTIONKEY = 1;

	/**
	 * Constructor used when decoding
	 */
	public PublicKeys(){
		super(false,2);
		init();
	}

	/**
	 * Constructor used when encoding
	 */
	public PublicKeys(PublicVerificationKey verificationKey, PublicEncryptionKey encryptionKey) throws IOException {
		super(false,2);
		init();
		set(VERIFICATIONKEY, verificationKey);
		set(ENCRYPTIONKEY,encryptionKey);
	}

	/**
	 * 
	 * @return verificationKey
	 */
	public PublicVerificationKey getVerificationKey(){
		return (PublicVerificationKey) get(VERIFICATIONKEY);
	}
	
	/**
	 * 
	 * @return encryptionKey
	 */
	public PublicEncryptionKey getEncryptionKey(){
		return (PublicEncryptionKey) get(ENCRYPTIONKEY);
	}
	
	private void init(){
		addField(VERIFICATIONKEY, false, new PublicVerificationKey(), null);
		addField(ENCRYPTIONKEY, true, new PublicEncryptionKey(), null);
		
	}
	
	@Override
	public String toString() {
		String encKeyString = getEncryptionKey() != null ? getEncryptionKey().toString().replace("PublicEncryptionKey ","") : "NONE";
		return "PublicKeys [verificationKey=" + getVerificationKey().toString().replaceAll("PublicVerificationKey ","") + ",encryptionKey=" + encKeyString +"]";
	}
}

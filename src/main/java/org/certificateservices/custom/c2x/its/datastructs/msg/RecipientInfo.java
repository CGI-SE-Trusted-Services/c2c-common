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
package org.certificateservices.custom.c2x.its.datastructs.msg;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

import org.certificateservices.custom.c2x.common.Encodable;
import org.certificateservices.custom.c2x.its.datastructs.basic.HashedId8;
import org.certificateservices.custom.c2x.its.datastructs.basic.PublicKeyAlgorithm;

/**
 * This structure contains information for a message's recipient. This information is used to distribute recipient-specific
 * data. cert_id determines the 8 octet identifier for the recipient's certificate. Depending on the value of
 * pk_encryption, the following additional data shall be given:
 * <li> ecies_nistp256: an encrypted key contained in an EciesNistP256EncryptedKey structure shall be given.
 * <li> unknown: in all other cases, a variable-length vector containing opaque data encoding an encrypted key 
 * shall be given. Currently not supported.
 * 
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class RecipientInfo implements Encodable{
	

    private HashedId8 certId;	
	private PublicKeyAlgorithm publicKeyAlgorithm;
	private EciesNistP256EncryptedKey pkEncryption;
	

	/**
	 * Main constructor of a RecipientInfo for a key using the ecies_nistp256 algorithm
	 * 
	 * @param certId This information is used to distribute recipient-specific data. cert_id determines the 8 octet 
	 * identifier for the recipient's certificate.
	 * @param pkEncryption 
	 */
	public RecipientInfo(HashedId8 certId, EciesNistP256EncryptedKey pkEncryption){
		this.publicKeyAlgorithm = PublicKeyAlgorithm.ecies_nistp256;
		this.certId = certId;
		this.pkEncryption = pkEncryption;		
	}
	
	/**
	 * Constructor used during serializing.
	 * 
	 */
	public RecipientInfo(){
	}
	
	/** 
	 * @return This information is used to distribute recipient-specific data. cert_id determines the 8 octet 
	 * identifier for the recipient's certificate.
	 */
	public HashedId8 getCertId(){
		return certId;
	}
	
	/** 
	 * @return the related public key algorithm.
	 */
	public PublicKeyAlgorithm getPublicKeyAlgorithm(){
		return publicKeyAlgorithm;
	}
	
	/** 
	 * @return An encrypted key contained in an EciesNistP256EncryptedKey structure
	 */
	public EciesNistP256EncryptedKey getPkEncryption(){
		return pkEncryption;
	}


	@Override
	public void encode(DataOutputStream out) throws IOException {
		certId.encode(out);
		out.write(publicKeyAlgorithm.getByteValue());
		switch(publicKeyAlgorithm){
		case ecies_nistp256:
			pkEncryption.encode(out);	
			break;
		default:
			break;
		}
		
	}

	@Override
	public void decode(DataInputStream in) throws IOException {
		certId = new HashedId8();
		certId.decode(in);
		publicKeyAlgorithm = PublicKeyAlgorithm.getByValue(in.read());
		switch(publicKeyAlgorithm){
		case ecies_nistp256:
			pkEncryption = new EciesNistP256EncryptedKey(publicKeyAlgorithm);
			pkEncryption.decode(in);	
			break;
		default:
			break;
		}
			
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((certId == null) ? 0 : certId.hashCode());
		result = prime * result
				+ ((pkEncryption == null) ? 0 : pkEncryption.hashCode());
		result = prime
				* result
				+ ((publicKeyAlgorithm == null) ? 0 : publicKeyAlgorithm
						.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		RecipientInfo other = (RecipientInfo) obj;
		if (certId == null) {
			if (other.certId != null)
				return false;
		} else if (!certId.equals(other.certId))
			return false;
		if (pkEncryption == null) {
			if (other.pkEncryption != null)
				return false;
		} else if (!pkEncryption.equals(other.pkEncryption))
			return false;
		if (publicKeyAlgorithm != other.publicKeyAlgorithm)
			return false;
		return true;
	}

	@Override
	public String toString() {
		return "RecipientInfo [certId=" + certId + ", publicKeyAlgorithm="
				+ publicKeyAlgorithm + ", pkEncryption=" + pkEncryption + "]";
	}






	

}

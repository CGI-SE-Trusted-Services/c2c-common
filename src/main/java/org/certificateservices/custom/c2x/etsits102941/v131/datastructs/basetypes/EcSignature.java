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

import org.certificateservices.custom.c2x.asn1.coer.COERChoice;
import org.certificateservices.custom.c2x.asn1.coer.COERChoiceEnumeration;
import org.certificateservices.custom.c2x.asn1.coer.COEREncodable;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.secureddata.EtsiTs103097DataEncrypted;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.secureddata.EtsiTs103097DataSignedExternalPayload;

import java.io.IOException;

/**
 * Class representing EcSignature defined in ETSI TS 102 941 Base Types.
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class EcSignature extends COERChoice {


	private static final long serialVersionUID = 1L;

	public enum EcSignatureChoices implements COERChoiceEnumeration{
		encryptedEcSignature,
		ecSignature;

		@Override
		public COEREncodable getEmptyCOEREncodable() throws IOException {
			switch (this) {
				case encryptedEcSignature:
					return new EtsiTs103097DataEncrypted();
				case ecSignature:
				default:
					return new EtsiTs103097DataSignedExternalPayload();
			}
		}

		/**
		 * @return always false
		 */
		@Override
		public boolean isExtension() {
			return false;
		}
	}

	/**
	 * Constructor used when encoding of type encryptedEcSignature
	 */
	public EcSignature(EtsiTs103097DataEncrypted encryptedEcSignature) {
		super(EcSignatureChoices.encryptedEcSignature, encryptedEcSignature);
	}

	/**
	 * Constructor used when encoding of type ecSignature
	 */
	public EcSignature(EtsiTs103097DataSignedExternalPayload ecSignature) {
		super(EcSignatureChoices.ecSignature, ecSignature);
	}

	/**
	 * Constructor used when decoding
	 */
	public EcSignature(){
		super(EcSignatureChoices.class);
	}
			
	/**
	 * Returns the type of id.
	 */
	public EcSignatureChoices getType(){
		return (EcSignatureChoices) choice;
	}

	/**
	 *
	 * @return the returns the encryptedEcSignature value or null of type is not encryptedEcSignature.
	 */
	public EtsiTs103097DataEncrypted getEncryptedEcSignature(){
		if(getType() == EcSignatureChoices.encryptedEcSignature){
			return (EtsiTs103097DataEncrypted) getValue();
		}
		return null;
	}

	/**
	 *
	 * @return the returns the getEcSignature value or null of type is not getEcSignature.
	 */
	public EtsiTs103097DataSignedExternalPayload getEcSignature(){
		if(getType() == EcSignatureChoices.ecSignature){
			return (EtsiTs103097DataSignedExternalPayload) getValue();
		}
		return null;
	}

	@Override
	public String toString() {
		switch(getType()){
		  case encryptedEcSignature:
			  return "EcSignature [" + choice + "=" + getEncryptedEcSignature().toString().replace("EtsiTs103097DataEncrypted ", "").replaceAll("\n","\n  ") +"\n]";
		  case ecSignature:
			  default:
			return "EcSignature [" + choice + "=" + getEcSignature().toString().replace("EtsiTs103097DataSignedExternalPayload ", "").replaceAll("\n","\n  ") +"\n]";
		}
	}
	
}

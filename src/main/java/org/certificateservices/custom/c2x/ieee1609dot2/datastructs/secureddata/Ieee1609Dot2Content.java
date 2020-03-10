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
package org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata;

import java.io.IOException;

import org.certificateservices.custom.c2x.asn1.coer.COERChoice;
import org.certificateservices.custom.c2x.asn1.coer.COERChoiceEnumeration;
import org.certificateservices.custom.c2x.asn1.coer.COEREncodable;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Opaque;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.EncryptedData;

/**
 * In this structure: 
 * <p>
 * <li>unsecuredData indicates that the content is an OCTET STRING to be consumed outside the SDS.
 * <li>signedData indicates that the content has been signed according to this standard. 
 * <li>encryptedData indicates that the content has been encrypted according to this standard.
 * <li>signedCertificateRequest indicates that the content is a certificate request. Further specification of 
 * certificate requests is not provided in this version of this standard.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class Ieee1609Dot2Content extends COERChoice {
	
	
	private static final long serialVersionUID = 1L;
	
	public enum Ieee1609Dot2ContentChoices implements COERChoiceEnumeration{
		unsecuredData,
		signedData,
		encryptedData,
		signedCertificateRequest;

		@Override
		public COEREncodable getEmptyCOEREncodable() throws IOException {
			switch(this){
			case signedData:
				return new SignedData();
			case encryptedData:
				return new EncryptedData();
			case unsecuredData:
			case signedCertificateRequest:
			default:
				return new Opaque();
			}
		}

		/**
		 * @return always false, no extension exists.
		 */
		@Override
		public boolean isExtension() {
			return false;
		}
	}
	
	/**
	 * Constructor used when encoding of type unsecuredData or signedCertificateRequest
	 */
	public Ieee1609Dot2Content(Ieee1609Dot2ContentChoices type, Opaque data) {
		super(type, data);
	}
	
	/**
	 * Constructor used when encoding of type signedData
	 */
	public Ieee1609Dot2Content(SignedData data) {
		super(Ieee1609Dot2ContentChoices.signedData, data);
	}

	/**
	 * Constructor used when encoding of type encryptedData
	 */
	public Ieee1609Dot2Content(EncryptedData data) {
		super(Ieee1609Dot2ContentChoices.encryptedData, data);
	}

	/**
	 * Constructor used when decoding.
	 */
	public Ieee1609Dot2Content() {
		super(Ieee1609Dot2ContentChoices.class);
	}
		
	/**
	 * Returns the type of id.
	 */
	public Ieee1609Dot2ContentChoices getType(){
		return (Ieee1609Dot2ContentChoices) choice;
	}

	@Override
	public String toString() {
		return "Ieee1609Dot2Content [\n  " + choice + "=" + value.toString().replace("Opaque ", "").replace("SignedData ", "").replace("EncryptedData ", "").replaceAll("\n", "\n  ")+ "\n]";
	}
	
}

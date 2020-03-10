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
package org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert;

import java.io.IOException;

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.asn1.coer.COERChoice;
import org.certificateservices.custom.c2x.asn1.coer.COERChoiceEnumeration;
import org.certificateservices.custom.c2x.asn1.coer.COEREncodable;
import org.certificateservices.custom.c2x.asn1.coer.COERNull;
import org.certificateservices.custom.c2x.asn1.coer.COEROctetStream;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Hostname;

/**
 * This structure contains information that is used to identify the certificate holder if necessary.
 * <li>linkageData is used to identify the certificate for revocation purposes in the case of certificates that appear on linked certificate CRLs. See 5.1.3, 7.3 for further discussion.
 * <li>name is used to identify the certificate holder in the case of non-anonymous certificates. The contents of this field are a matter of policy and should be human-readable.
 * <li>binaryId supports identifiers that are not human-readable.
 * <li>none indicates that the certificate does not include an identifier.
 * <p>
 *     <b>Critical information fields:</b>If present, this is a critical information field as defined in 5.2.5. An
 *     implementation that does not recognize the choice indicated in this field shall reject a signed SPDU as invalid.
 * </p>
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class CertificateId extends COERChoice {
	
	
	private static final long serialVersionUID = 1L;
	
	public enum CertificateIdChoices implements COERChoiceEnumeration{
		linkageData,
		name,
		binaryId,
		none;

		@Override
		public COEREncodable getEmptyCOEREncodable() throws IOException {
			switch (this) {
			case linkageData:
				return new LinkageData();
			case name:
				return new Hostname();				
			case binaryId:
				return new COEROctetStream(1,64);
			default:
				return new COERNull();
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
	 * Constructor used when encoding of type linkageData
	 */
	public CertificateId(LinkageData linkageData) {
		super(CertificateIdChoices.linkageData, linkageData);
	}
	
	/**
	 * Constructor used when encoding of type name
	 */
	public CertificateId(Hostname name) {
		super(CertificateIdChoices.name, name);
	}
	
	/**
	 * Constructor used when encoding of type binaryId
	 */
	public CertificateId(byte[] binaryId) throws IOException {
		super(CertificateIdChoices.binaryId, new COEROctetStream(binaryId,1, 64));
	}
	

	/**
	 * Constructor used when encoding of type none and decoding.
	 */
	public CertificateId() {
		super(CertificateIdChoices.none,new COERNull());
		this.choiceEnum = CertificateIdChoices.class;
	}
		
	/**
	 * Returns the type of id.
	 */
	public CertificateIdChoices getType(){
		return (CertificateIdChoices) choice;
	}

	@Override
	public String toString() {
		switch(getType()){
		  case none:
			  return "CertificateId [" + choice +"]";
		  case binaryId:
			  return "CertificateId [" + choice + "=" + new String(Hex.encode(((COEROctetStream) value).getData())) +"]";
		  case name:
			  return "CertificateId [" + choice + "=" + value.toString().replace("Hostname ", "") +"]";
		  case linkageData:
			  default:
			return "CertificateId [" + choice + "=" + value.toString().replace("LinkageData ", "") +"]";
		}
	}
	
}

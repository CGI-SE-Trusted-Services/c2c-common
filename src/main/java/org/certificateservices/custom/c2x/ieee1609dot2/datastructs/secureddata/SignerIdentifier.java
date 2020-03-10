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

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.asn1.coer.COERChoice;
import org.certificateservices.custom.c2x.asn1.coer.COERChoiceEnumeration;
import org.certificateservices.custom.c2x.asn1.coer.COEREncodable;
import org.certificateservices.custom.c2x.asn1.coer.COERNull;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId8;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.SequenceOfCertificate;


/**
 * This structure allows the recipient of data to determine which keying material to use to authenticate the data. 
 * It also indicates the verification type to be used to generate the hash for verification, as specified in 
 * <li>If the choice indicated is digest:
 * <br>- The structure contains the HashedId8 of the relevant certificate, The HashedId8 is calculated with the whole-certificate
 * hash algorithm, determined as described in 6.4.3.
 * <br>- The verification type is certificate.
 * <li>If the choice indicated is certificate:
 * <br>- The structure contains one or more Certificate structures, in order such that the first certificate is the authorization certificate and 
 * each subsequent certificate is the issuer of the one before it.
 * <br>- The verification type is certificate and the certificate data passed to the hash function as specified in 5.3.1 is the authorization certificate.
 * <li>If the choice indicated is self:
 * <br>- The structure does not contain any data beyond the indication that the choice value is self.
 * <br>- The verification type is self-signed.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class SignerIdentifier extends COERChoice {
	
	
	private static final long serialVersionUID = 1L;
	
	public enum SignerIdentifierChoices implements COERChoiceEnumeration{
		digest,
		certificate,
		self;

		@Override
		public COEREncodable getEmptyCOEREncodable()  {
	      switch(this){
	      case digest:
	    	  return new HashedId8();
	      case certificate:
	    	  return new SequenceOfCertificate();
	      case self:
	      default:
	    	  return  new COERNull();
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
	 * Constructor used when encoding of type digest
	 */
	public SignerIdentifier(HashedId8 digest) {
		super(SignerIdentifierChoices.digest, digest);
	}
	
	/**
	 * Constructor used when encoding of type certificate
	 */
	public SignerIdentifier(SequenceOfCertificate certificates) {
		super(SignerIdentifierChoices.certificate, certificates);
	}
	

	/**
	 * Constructor used when encoding self or, decoding.
	 */
	public SignerIdentifier() {
		super(SignerIdentifierChoices.self,new COERNull());
		this.choiceEnum = SignerIdentifierChoices.class;
	}
		
	/**
	 * Returns the type of id.
	 */
	public SignerIdentifierChoices getType(){
		return (SignerIdentifierChoices) choice;
	}

	@Override
	public String toString() {		
		switch(getType()){
		case self:
			return "SignerIdentifier [" + choice +"]";
		case digest:
			return "SignerIdentifier [" + choice + "=" + new String(Hex.encode(((HashedId8) value).getData())) +"]";
		case certificate:
		default:
			return "SignerIdentifier [" + choice + "=" + value.toString().replace("SequenceOfCertificate ", "") +"]";
		}	
	}
	
}

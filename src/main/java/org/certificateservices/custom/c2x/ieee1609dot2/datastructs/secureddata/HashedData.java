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
import org.certificateservices.custom.c2x.asn1.coer.COEROctetStream;

/**
 * This structure contains the hash of some data with a specified hash algorithm. 
 * <p>
 * The only hash algorithm supported in this version of this standard is SHA-256.
 * <p>
 * <b>Critical information fields:</b> If present, this is a critical information field as defined in 5.2.5. An implementation 
 * that does not recognize the indicated CHOICE for this type when verifying a signed SPDU shall indicate that 
 * the signed SPDU is invalid.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class HashedData extends COERChoice {
	
	
	private static final long serialVersionUID = 1L;
	
	public enum HashedDataChoices implements COERChoiceEnumeration{
		sha256HashedData;

		@Override
		public COEREncodable getEmptyCOEREncodable()  {
	      return new COEROctetStream(32,32);
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
	 * Constructor used when encoding of type sha256HashedData
	 */
	public HashedData(HashedDataChoices type, byte[] hash) throws IOException{
		super(type, new COEROctetStream(hash, 32, 32));
	}
	

	/**
	 * Constructor used when decoding.
	 */
	public HashedData() {
		super(HashedDataChoices.class);
	}
		
	/**
	 * Returns the type of id.
	 */
	public HashedDataChoices getType(){
		return (HashedDataChoices) choice;
	}

	@Override
	public String toString() {
		return "HashedData [" + choice + "=" + new String(Hex.encode(((COEROctetStream)value).getData())) + "]";
	}
	
}

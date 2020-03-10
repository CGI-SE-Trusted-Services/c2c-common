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
package org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist;

import org.certificateservices.custom.c2x.asn1.coer.COERChoice;
import org.certificateservices.custom.c2x.asn1.coer.COERChoiceEnumeration;
import org.certificateservices.custom.c2x.asn1.coer.COEREncodable;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId8;

import java.io.IOException;

/**
 * Class representing CtlDelete defined in ETSI TS 102 941 Trust List Types.
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class CtlDelete extends COERChoice {

	private static final long serialVersionUID = 1L;

	public enum CtlDeleteChoices implements COERChoiceEnumeration{
		cert,
		dc;

		@Override
		public COEREncodable getEmptyCOEREncodable() throws IOException {
			switch (this) {
				case cert:
					return new HashedId8();
				case dc:
				default:
					return new DcDelete();
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
	 * Constructor used when encoding of type cert
	 */
	public CtlDelete(HashedId8 cert) {
		super(CtlDeleteChoices.cert, cert);
	}

	/**
	 * Constructor used when encoding of type dc
	 */
	public CtlDelete(DcDelete dc) {
		super(CtlDeleteChoices.dc, dc);
	}

	/**
	 * Constructor used when decoding
	 */
	public CtlDelete(){
		super(CtlDeleteChoices.class);
	}
			
	/**
	 * Returns the type of id.
	 */
	public CtlDeleteChoices getType(){
		return (CtlDeleteChoices) choice;
	}

	/**
	 *
	 * @return the returns the cert value or null of type is not cert.
	 */
	public HashedId8 getCert(){
		if(getType() == CtlDeleteChoices.cert){
			return (HashedId8) getValue();
		}
		return null;
	}

	/**
	 *
	 * @return the returns the getEcSignature value or null of type is not getEcSignature.
	 */
	public DcDelete getDc(){
		if(getType() == CtlDeleteChoices.dc){
			return (DcDelete) getValue();
		}
		return null;
	}

	@Override
	public String toString() {
		switch(getType()){
		  case cert:
			  return "CtlDelete [" + choice + "=" + getCert().toString().replace("HashedId8 ", "") +"]";
		  case dc:
			  default:
			return "CtlDelete [" + choice + "=" + getDc().toString().replace("DcDelete ", "") +"]";
		}
	}
	
}

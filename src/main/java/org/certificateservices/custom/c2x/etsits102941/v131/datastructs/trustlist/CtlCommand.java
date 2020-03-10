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

import java.io.IOException;

/**
 * Class representing CtlCommand defined in ETSI TS 102 941 Trust List Types.
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class CtlCommand extends COERChoice {

	private static final long serialVersionUID = 1L;

	public enum CtlCommandChoices implements COERChoiceEnumeration{
		add,
		delete;

		@Override
		public COEREncodable getEmptyCOEREncodable() throws IOException {
			switch (this) {
				case add:
					return new CtlEntry();
				case delete:
				default:
					return new CtlDelete();
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
	public CtlCommand(CtlEntry ctlEntry) {
		super(CtlCommandChoices.add, ctlEntry);
	}

	/**
	 * Constructor used when encoding of type dc
	 */
	public CtlCommand(CtlDelete ctlDelete) {
		super(CtlCommandChoices.delete, ctlDelete);
	}

	/**
	 * Constructor used when decoding
	 */
	public CtlCommand(){
		super(CtlCommandChoices.class);
	}
			
	/**
	 * Returns the type of id.
	 */
	public CtlCommandChoices getType(){
		return (CtlCommandChoices) choice;
	}

	/**
	 *
	 * @return the returns the ctlEntry (add) value or null of type is not add.
	 */
	public CtlEntry getCtlEntry(){
		if(getType() == CtlCommandChoices.add){
			return (CtlEntry) getValue();
		}
		return null;
	}

	/**
	 *
	 * @return the returns the ctlDelete (delete) value or null of type is not delete.
	 */
	public CtlDelete getCtlDelete(){
		if(getType() == CtlCommandChoices.delete){
			return (CtlDelete) getValue();
		}
		return null;
	}

	@Override
	public String toString() {
		switch(getType()){
		  case add:
			  return "CtlCommand [" + choice + "=" + getCtlEntry().toString().replace("CtlEntry ", "").replaceAll("\n","\n  ")  +"]";
			case delete:
			  default:
				  return "CtlCommand [" + choice + "=" + getCtlDelete().toString().replace("CtlDelete ", "") +"]";
		}
	}
	
}

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
import org.certificateservices.custom.c2x.common.BadArgumentException;

import java.io.IOException;

/**
 * Class representing CtlEntry defined in ETSI TS 102 941 Trust List Types.
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class CtlEntry extends COERChoice {

	private static final long serialVersionUID = 1L;

	public enum CtlEntryChoices implements COERChoiceEnumeration{
		rca,
		ea,
		aa,
		dc,
		tlm;

		@Override
		public COEREncodable getEmptyCOEREncodable() throws IOException {
			switch (this) {
				case rca:
					return new RootCaEntry();
				case ea:
					return new EaEntry();
				case aa:
					return new AaEntry();
				case dc:
					return new DcEntry();
				case tlm:
				default:
					return new TlmEntry();
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
	 * Constructor used when encoding of type rca
	 */
	public CtlEntry(RootCaEntry rcaEntry)  {
		super(CtlEntryChoices.rca, rcaEntry);
	}

	/**
	 * Constructor used when encoding of type ea
	 */
	public CtlEntry(EaEntry eaEntry){
		super(CtlEntryChoices.ea, eaEntry);
	}

	/**
	 * Constructor used when encoding of type aa
	 */
	public CtlEntry(AaEntry aaEntry) {
		super(CtlEntryChoices.aa, aaEntry);
	}

	/**
	 * Constructor used when encoding of type dc
	 */
	public CtlEntry(DcEntry dcEntry) {
		super(CtlEntryChoices.dc, dcEntry);
	}

	/**
	 * Constructor used when encoding of type tlm
	 */
	public CtlEntry(TlmEntry tlmEntry) {
		super(CtlEntryChoices.tlm, tlmEntry);
	}

	/**
	 * Constructor used when decoding
	 */
	public CtlEntry(){
		super(CtlEntryChoices.class);
	}

	/**
	 * Returns the type of id.
	 */
	public CtlEntryChoices getType(){
		return (CtlEntryChoices) choice;
	}

	/**
	 *
	 * @return the returns the rcaEntry value or null of type is not cert.
	 */
	public RootCaEntry getRcaEntry(){
		if(getType() == CtlEntryChoices.rca){
			return (RootCaEntry) getValue();
		}
		return null;
	}

	/**
	 *
	 * @return the returns the eaEntry value or null of type is not cert.
	 */
	public EaEntry getEaEntry(){
		if(getType() == CtlEntryChoices.ea){
			return (EaEntry) getValue();
		}
		return null;
	}

	/**
	 *
	 * @return the returns the aaEntry value or null of type is not cert.
	 */
	public AaEntry getAaEntry(){
		if(getType() == CtlEntryChoices.aa){
			return (AaEntry) getValue();
		}
		return null;
	}

	/**
	 *
	 * @return the returns the dcEntry value or null of type is not cert.
	 */
	public DcEntry getDcEntry(){
		if(getType() == CtlEntryChoices.dc){
			return (DcEntry) getValue();
		}
		return null;
	}

	/**
	 *
	 * @return the returns the tlmEntry value or null of type is not cert.
	 */
	public TlmEntry getTlmEntry(){
		if(getType() == CtlEntryChoices.tlm){
			return (TlmEntry) getValue();
		}
		return null;
	}


	@Override
	public String toString() {
		switch(getType()){
			case rca:
				return "CtlEntry [" + choice + "=" + getRcaEntry().toString().replace("RootCaEntry ", "").replaceAll("\n","\n  ") +"\n]";
			case ea:
				return "CtlEntry [" + choice + "=" + getEaEntry().toString().replace("EaEntry ", "").replaceAll("\n","\n  ") +"\n]";
			case aa:
				return "CtlEntry [" + choice + "=" + getAaEntry().toString().replace("AaEntry ", "").replaceAll("\n","\n  ") +"\n]";
			case dc:
				return "CtlEntry [" + choice + "=" + getDcEntry().toString().replace("DcEntry ", "").replaceAll("\n","\n  ") +"\n]";
			case tlm:
			default:
				return "CtlEntry [" + choice + "=" + getTlmEntry().toString().replace("TlmEntry ", "").replaceAll("\n","\n  ") +"\n]";
		}
	}

}

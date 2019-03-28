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
package org.certificateservices.custom.c2x.etsits102941.v121.datastructs.trustlist;

import org.certificateservices.custom.c2x.etsits102941.v121.datastructs.basetypes.Version;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Time32;

/**
 * Class representing ToBeSignedTlmCtl defined in ETSI TS 102 941 Trust List Types
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class ToBeSignedTlmCtl extends CtlFormat {

	private static final long serialVersionUID = 1L;

	/**
	 * Constructor used when decoding
	 */
	public ToBeSignedTlmCtl(){
		super();
	}

	/**
	 * Constructor used when encoding
	 */
	public ToBeSignedTlmCtl(Version version, Time32 nextUpdate, boolean isFullCtl, int ctlSequence, CtlCommand[] ctlCommands){
		super(version,nextUpdate,isFullCtl,ctlSequence,ctlCommands);
		validateToBeSignedRcaCtl(ctlCommands);
	}

	protected void validateToBeSignedRcaCtl(CtlCommand[] ctlCommands) throws IllegalArgumentException{
		for(CtlCommand cmd : ctlCommands){
			if(cmd.getType() == CtlCommand.CtlCommandChoices.add){
				if(cmd.getCtlEntry().getType() == CtlEntry.CtlEntryChoices.ea ||
				   cmd.getCtlEntry().getType() == CtlEntry.CtlEntryChoices.aa){
					throw new IllegalArgumentException("Invalid ToBeSignedTlmCtl, cannot contain ctl commands for add " + cmd.getCtlEntry().getType());
				}
			}
		}
	}

    @Override
    public String toString() {
		return super.toString().replaceAll("CtlFormat ","ToBeSignedTlmCtl ");
    }

}

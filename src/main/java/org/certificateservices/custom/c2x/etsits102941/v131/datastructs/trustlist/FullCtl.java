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

import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.Version;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Time32;

/**
 * Class representing FullCtl defined in ETSI TS 102 941 Trust List Types
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class FullCtl extends CtlFormat {

	private static final long serialVersionUID = 1L;

	/**
	 * Constructor used when decoding
	 */
	public FullCtl(){
		super();
	}

	/**
	 * Constructor used when encoding
	 */
	public FullCtl(Version version, Time32 nextUpdate, int ctlSequence, CtlCommand[] ctlCommands){
		super(version,nextUpdate,true,ctlSequence,ctlCommands);
	}


    @Override
    public String toString() {
		return super.toString().replaceAll("CtlFormat ","FullCtl ");
    }

}

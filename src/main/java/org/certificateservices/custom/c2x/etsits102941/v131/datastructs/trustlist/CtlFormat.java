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

import org.certificateservices.custom.c2x.asn1.coer.*;
import org.certificateservices.custom.c2x.common.BadArgumentException;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.Version;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Time32;

import java.io.IOException;
import java.util.Arrays;

/**
 * Class representing CtlFormat defined in ETSI TS 102 941 Trust List Types
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class CtlFormat extends COERSequence {

	private static final long serialVersionUID = 1L;

	private static final int VERSION = 0;
	private static final int NEXTUPDATE = 1;
	private static final int ISFULLCTL = 2;
	private static final int CTLSEQUENCE = 3;
	private static final int CTLCOMMANDS = 4;

	/**
	 * Constructor used when decoding
	 */
	public CtlFormat(){
		super(true,5);
		init();
	}

	/**
	 * Constructor used when encoding
	 */
	public CtlFormat(Version version, Time32 nextUpdate, boolean isFullCtl, int ctlSequence,
					 CtlCommand[] ctlCommands) throws IOException, BadArgumentException {
		super(true,5);
		init();

		set(VERSION, version);
        set(NEXTUPDATE, nextUpdate);
		set(ISFULLCTL, new COERBoolean(isFullCtl));
		set(CTLSEQUENCE, new COERInteger(ctlSequence, 0,255));
		set(CTLCOMMANDS, new COERSequenceOf(ctlCommands));
		validateCtlFormat(isFullCtl, ctlCommands);
	}

	/**
	 *
	 * @return the version value
	 */
	public Version getVersion(){
		return (Version) get(VERSION);
	}

	/**
	 *
	 * @return the nextUpdate value
	 */
	public Time32 getNextUpdate(){
		return (Time32) get(NEXTUPDATE);
	}

	/**
	 *
	 * @return the isFullCtl value
	 */
	public boolean isFullCtl(){
		return ((COERBoolean) get(ISFULLCTL)).isValue();
	}

	/**
	 *
	 * @return the ctlSequence value
	 */
	public int getCtlSequence(){
		return (int) ((COERInteger) get(CTLSEQUENCE)).getValueAsLong();
	}

	/**
	 *
	 * @return the CtlCommand values
	 */
	public CtlCommand[] getCtlCommands(){
		COEREncodable[] values = ((COERSequenceOf) get(CTLCOMMANDS)).getSequenceValues();
		return Arrays.copyOf(values,values.length,CtlCommand[].class);
	}

	protected void validateCtlFormat(boolean isFullCtl, CtlCommand[] ctlCommands) throws BadArgumentException {
		if(isFullCtl){
			for(CtlCommand cmd : ctlCommands){
				if(cmd.getType() == CtlCommand.CtlCommandChoices.delete){
					throw new BadArgumentException("Illegal CtlFormat, fullCtl cannot have delete ctl commands.");
				}
			}
		}
	}

	private void init(){
		addField(VERSION, false, new Version(), null);
        addField(NEXTUPDATE, false, new Time32(), null);
		addField(ISFULLCTL, false, new COERBoolean(), null);
		addField(CTLSEQUENCE, false, new COERInteger(0,255), null);
		addField(CTLCOMMANDS, false, new COERSequenceOf(new CtlCommand()), null);
	}

    @Override
    public String toString() {
		String commandsString = "\n";
		if(getCtlCommands().length == 0){
			commandsString = "NONE";
		}else {
			CtlCommand[] ctlCommands = getCtlCommands();
			for (int i = 0; i<ctlCommands.length; i++) {
				commandsString += "    " + ctlCommands[i].toString().replaceAll("CtlCommand ", "").replaceAll("\n", "\n  ");
				if(i < ctlCommands.length-1){
					commandsString += "\n";
				}
			}
		}

        return "CtlFormat [\n" +
                        "  version=" + getVersion().getValueAsLong() + "\n" +
				        "  nextUpdate=" + getNextUpdate() + "\n" +
                        "  isFullCtl=" + isFullCtl() + "\n" +
				        "  ctlSequence=" + getCtlSequence() + "\n" +
			         	"  ctlCommands=" + commandsString + "\n" +
                        "]";
    }

}

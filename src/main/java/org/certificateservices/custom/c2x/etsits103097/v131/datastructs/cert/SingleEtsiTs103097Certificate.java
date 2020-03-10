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
package org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert;

import org.certificateservices.custom.c2x.asn1.coer.COERSequence;

import java.io.IOException;

/**
 * Sequence of only one EtsiTs103097Certificate
 */
public class SingleEtsiTs103097Certificate extends COERSequence {

    private static final long serialVersionUID = 1L;

    private static final int ONLY = 0;

    /**
     * Constructor used when decoding
     */
    public SingleEtsiTs103097Certificate(){
        super(false,1);
        init();
    }

    /**
     * Constructor used when encoding
     */
    public SingleEtsiTs103097Certificate(EtsiTs103097Certificate certificate) throws IOException {
        super(false,1);
        init();
        set(ONLY, certificate);
    }

    /**
     *
     * @return EtsiTs103097Certificate only
     */
    public EtsiTs103097Certificate getOnly(){
        return (EtsiTs103097Certificate) get(ONLY);
    }


    private void init(){
        addField(ONLY, false, new EtsiTs103097Certificate(), null);

    }

    @Override
    public String toString() {
        return "SingleEtsiTs103097Certificate [only=" + getOnly().toString() + "]";
    }
}

package org.certificateservices.custom.c2x.common;

import java.util.Arrays;
import java.util.List;

/**
 * Enumeration listing available country code value according to
 * C-ITS Point of Contact (CPOC) RCA certificate requirements & best practices. Draft v0.5, October 2019
 *
 * @author Lu Han 2020-03-10
 */
public class CountryCode {

    private final static int AUSTRIA = 40;
    private final static int BELGIUM = 56;
    private final static int BULGARIA = 100;
    private final static int CROATIA = 191;
    private final static int REPUBLICOFCYPRUS = 196;
    private final static int CZECHREPUBLIC = 203;
    private final static int DENMARK = 208;
    private final static int ESTONIA = 233;
    private final static int FINLAND = 246;
    private final static int FRANCE = 250;
    private final static int GERMANY = 276;
    private final static int GREECE = 300;
    private final static int HUNGARY = 348;
    private final static int IRELAND = 372;
    private final static int ITALY = 380;
    private final static int LATVIA = 428;
    private final static int LITHUANIA = 440;
    private final static int LUXEMBOURG = 442;
    private final static int MALTA = 470;
    private final static int NETHERLANDS = 528;
    private final static int POLAND = 616;
    private final static int PORTUGAL = 620;
    private final static int ROMANIA = 642;
    private final static int SLOVAKIA = 703;
    private final static int SLOVENIA = 705;
    private final static int SPAIN = 724;
    private final static int SWEDEN = 752;
    private final static int UK = 826;

    static boolean checkCountryCode(int code) {
        List<Integer> countryCode = Arrays.asList(AUSTRIA, BELGIUM, BULGARIA, CROATIA, REPUBLICOFCYPRUS, CZECHREPUBLIC,
                DENMARK, ESTONIA, FINLAND, FRANCE, GERMANY, GREECE, HUNGARY, IRELAND, ITALY, LATVIA, LITHUANIA, LUXEMBOURG,
                MALTA, NETHERLANDS, POLAND, PORTUGAL, ROMANIA, SLOVAKIA, SLOVENIA, SPAIN, SWEDEN, UK);
        for(int i=0; i<countryCode.size(); i++){
            if(code == countryCode.get(i)){
                return true;
            }
        }
        return false;
    }
}
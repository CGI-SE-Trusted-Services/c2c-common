package org.certificateservices.custom.c2x.common;
import spock.lang.Specification;

import static org.certificateservices.custom.c2x.common.CountryCode.*;

/**
 * Unit test for CountryCode
 *
 * @author Lu Han 2020-03-10
 */
class CountryCodeSpec extends Specification {

    def "test checkCountryCode method"(){
        expect:
        checkCountryCode(40)        // AUSTRIA
        checkCountryCode(56)        // BELGIUM
        checkCountryCode(100)       // BULGARIA
        checkCountryCode(191)       // CROATIA
        checkCountryCode(196)       // REPUBLICOFCYPRUS
        checkCountryCode(203)       // CZECHREPUBLIC
        checkCountryCode(208)       // DENMARK
        checkCountryCode(233)       // ESTONIA
        checkCountryCode(246)       // FINLAND
        checkCountryCode(250)       // FRANCE
        checkCountryCode(276)       // GERMANY
        checkCountryCode(300)       // GREECE
        checkCountryCode(348)        // HUNGARY
        checkCountryCode(372)        // IRELAND
        checkCountryCode(380)        // ITALY
        checkCountryCode(428)        // LATVIA
        checkCountryCode(440)        // LITHUANIA
        checkCountryCode(442)        // LUXEMBOURG
        checkCountryCode(470)        // MALTA
        checkCountryCode(528)        // NETHERLANDS
        checkCountryCode(616)        // POLAND
        checkCountryCode(620)        // PORTUGAL
        checkCountryCode(642)        // ROMANIA
        checkCountryCode(703)        // SLOVAKIA
        checkCountryCode(705)        // SLOVENIA
        checkCountryCode(724)        // SPAIN
        checkCountryCode(752)        // SWEDEN
        checkCountryCode(826)        // UK

        !checkCountryCode(1)
        !checkCountryCode(123)
    }
}
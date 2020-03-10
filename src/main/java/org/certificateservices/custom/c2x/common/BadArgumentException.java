package org.certificateservices.custom.c2x.common;

/**
 * Class indicating a method was called with bad arguments.
 *
 * @author Philip 2020-03-09
 */
public class BadArgumentException extends Exception{

    /**
     * Class indicating a method was called with bad arguments.
     * @param message descriptive error message of the error.
     */
    public BadArgumentException(String message) {
        super(message);
    }

    /**
     * Class indicating a method was called with bad arguments.
     *
     * @param message descriptive error message of the error.
     * @param cause cause of the exception
     */
    public BadArgumentException(String message, Throwable cause) {
        super(message, cause);
    }
}

/*
 *  Copyright 2006-2021 WebPKI.org (http://webpki.org).
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package org.webpki.util;

import java.text.SimpleDateFormat;

import java.util.Calendar;
import java.util.EnumSet;
import java.util.GregorianCalendar;
import java.util.SimpleTimeZone;
import java.util.TimeZone;

import java.util.regex.Pattern;

/**
 * Encodes/decodes ISO time data.
 */
public class ISODateTime {

    private ISODateTime() {}  // No instantiation please
    
    /**
     * Enumeration of ISO time features.
     */
    public static enum DatePatterns {
        /**
         * UTC time zone.
         * <p>
         * Note: you must specify {@link LOCAL}, {@link UTC}, 
         * or both for {@link #decode(String, EnumSet<DatePatterns>)}.
         * </p>
         */
        UTC,
        
        /**
         * Local time zone.
         */
        LOCAL,
        
        /**
         * Accept milliseconds (up to 3 digits) for 
         * {@link #decode(String, EnumSet<DatePatterns>)}.
         */
        MILLISECONDS,
        
        /**
         * Accept microseconds (up to 6 digits) for 
         * {@link #decode(String, EnumSet<DatePatterns>)}.
         * <p>
         * DO NOT USE for {@link #encode(GregorianCalendar, EnumSet<DatePatterns>)}.
         * </p>
         */
        MICROSECONDS,
        
        /**
         * Accept nanoseconds (up to 9 digits) for 
         * {@link #decode(String, EnumSet<DatePatterns>)}.
         * <p>
         * DO NOT USE for {@link #encode(GregorianCalendar, EnumSet<DatePatterns>)}.
         * </p>
         */
        NANOSECONDS};
                                     
    public static final EnumSet<DatePatterns> UTC_NO_SUBSECONDS = EnumSet.of(DatePatterns.UTC);
    public static final EnumSet<DatePatterns> LOCAL_NO_SUBSECONDS = EnumSet.of(DatePatterns.LOCAL);
    
    /**
     * For {@link #decode(String, EnumSet<DatePatterns>)} only: accept the full syntax.
     */
    public static final EnumSet<DatePatterns> COMPLETE = EnumSet.allOf(DatePatterns.class);

    static final Pattern DATE_PATTERN = Pattern.compile("(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d" +
                                                        "{2})(\\.\\d{1,9})?([+-]\\d{2}:\\d{2}|Z)");

    
    /**
     * Decodes an ISO formatted dateTime string.
     * <p>
     * <i>Always:</i> <code>yyyy-mm-ddThh:mm:ss</code><br>
     * <i>Optionally:</i> a '.' followed by 1-9 digits holding fractions of a second<br>
     * <i>Finally:</i> 'Z' for UTC or an UTC time-zone difference 
     * expressed as <code>+hh:mm</code> or <code>-hh:mm</code>
     * </p>
     *
     * @param dateTime String to be parsed
     * @param constraints Permitted format(s)
     * @return GregorianCalendar
     */
    public static GregorianCalendar decode(String dateTime, 
                                           EnumSet<DatePatterns> constraints) {

        if (!DATE_PATTERN.matcher(dateTime).matches()) {
            throw new IllegalArgumentException("DateTime syntax error: " + dateTime);
        }
        
        GregorianCalendar gc = new GregorianCalendar();
        gc.clear();

        gc.set(GregorianCalendar.ERA, GregorianCalendar.AD);
        gc.set(GregorianCalendar.YEAR, Integer.parseInt(dateTime.substring(0, 4)));
        gc.set(GregorianCalendar.MONTH, Integer.parseInt(dateTime.substring(5, 7)) - 1);

        gc.set(GregorianCalendar.DAY_OF_MONTH, Integer.parseInt(dateTime.substring(8, 10)));

        gc.set(GregorianCalendar.HOUR_OF_DAY, Integer.parseInt(dateTime.substring(11, 13)));

        gc.set(GregorianCalendar.MINUTE, Integer.parseInt(dateTime.substring(14, 16)));

        gc.set(GregorianCalendar.SECOND, Integer.parseInt(dateTime.substring(17, 19)));

        String subSeconds = null;

        // Find time zone info.
        if (dateTime.endsWith("Z")) {
            if (!constraints.contains(DatePatterns.UTC)) {
                bad(dateTime);
            }
            gc.setTimeZone(TimeZone.getTimeZone("UTC"));
            subSeconds = dateTime.substring(19, dateTime.length() - 1);
        } else {
            if (!constraints.contains(DatePatterns.LOCAL)) {
                bad(dateTime);
            }
            int factor = 60 * 1000;
            int i = dateTime.indexOf('+');
            if (i < 0) {
                i = dateTime.lastIndexOf('-');
                factor = -factor;
            }
            subSeconds = dateTime.substring(19, i);
            int tzHour = Integer.parseInt(dateTime.substring(++i, i + 2));
            int tzMinute = Integer.parseInt(dateTime.substring(i + 3, i + 5));
            gc.setTimeZone(new SimpleTimeZone(((60 * tzHour) + tzMinute) * factor, ""));
        }
        if (subSeconds.length() > 0) {
            if (!constraints.contains(DatePatterns.NANOSECONDS)) {
                if (constraints.contains(DatePatterns.MILLISECONDS)) {
                    if (subSeconds.length() > 4) {
                        bad(dateTime);
                    }
                } else if (constraints.contains(DatePatterns.MICROSECONDS)) {
                    if (subSeconds.length() > 7) {
                        bad(dateTime);
                    }
                } else {
                    // Forgot to specify?
                    bad(dateTime);
                }
            }
            // Milliseconds is the only thing we can eat though
            subSeconds = subSeconds.substring(1, 
                    subSeconds.length() > 4 ? 4 : subSeconds.length());
            int fraction = Integer.parseInt(subSeconds) * 100;
            for (int q = 1; q < subSeconds.length(); q++) {
                fraction /= 10;
            }
            gc.set(GregorianCalendar.MILLISECOND, fraction);
        }
        return gc;
    }

    private static void bad(String dateTime) {
        throw new IllegalArgumentException("DateTime format doesn't match specification: " + 
                                           dateTime);
    }

    /**
     * Encodes an ISO formatted dateTime string.
     * <p>
     * <i>Always:</i> <code>yyyy-mm-ddThh:mm:ss</code><br>
     * <i>Optional:</i> a '.' followed by 3 digits holding milliseconds<br>
     * <i>UTC:</i> Append 'Z'<br>
     * <i>Local time:</i> Append time-zone difference expressed as
     * <code>+hh:mm</code> or <code>-hh:mm</code>
     * </p>
     * <p>
     * If {@link DatePatterns#UTC} is defined, UTC mode is used, else local time format is assumed.
     * </p>
     * <p>
     * If {@link DatePatterns#MILLISECONDS} is defined, milliseconds (<cde>.nnn</code>] are included in the output, else only seconds are used.
     * </p> 
     * 
     * @param dateTime The date/time object
     * @param format Format
     * @return String
     */
    public static String encode(GregorianCalendar dateTime, EnumSet<DatePatterns> format) {
        SimpleDateFormat sdf = new SimpleDateFormat(
                format.contains(DatePatterns.MILLISECONDS) ?
                               "yyyy-MM-dd'T'HH:mm:ss.SSS" : "yyyy-MM-dd'T'HH:mm:ss");
        sdf.setTimeZone(format.contains(DatePatterns.UTC) ? 
                              TimeZone.getTimeZone("UTC") : dateTime.getTimeZone());
        StringBuilder s = new StringBuilder(sdf.format(dateTime.getTime()));
        if (format.contains(DatePatterns.UTC)) {
           s.append('Z');
        } else {
           int tzo = (dateTime.get(Calendar.ZONE_OFFSET) + 
                      dateTime.get(Calendar.DST_OFFSET)) / (60 * 1000);
           if (tzo < 0) {
                tzo = - tzo;
                s.append('-');
            } else {
                s.append('+');
            }
            int tzh = tzo / 60, tzm = tzo % 60;
            s.append(tzh < 10 ? "0" : "")
             .append(tzh)
             .append(tzm < 10 ? ":0" : ":")
             .append(tzm);
        }
        return s.toString();
    }
}

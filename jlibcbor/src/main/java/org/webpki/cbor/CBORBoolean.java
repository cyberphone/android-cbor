/*
 *  Copyright 2006-2024 WebPKI.org (https://webpki.org).
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      https://apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package org.webpki.cbor;

import static org.webpki.cbor.CBORInternal.*;

/**
 * Class for holding CBOR <code>bool</code> objects.
 */
public class CBORBoolean extends CBORObject {

    static final byte[] TRUE  = {(byte)MT_TRUE};
    static final byte[] FALSE = {(byte)MT_FALSE};

    boolean value;

    /**
     * Creates a CBOR <code>bool/code>.
     * 
     * @param value <code>true</code> or <code>false</code>
     */
    public CBORBoolean(boolean value) {
        this.value = value;
    }

    @Override
    byte[] internalEncode() {
        return value ? TRUE : FALSE;
    }

    @Override
    void internalToString(CborPrinter cborPrinter) {
        cborPrinter.append(String.valueOf(value));
    }
}

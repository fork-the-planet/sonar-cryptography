/*
 * Sonar Cryptography Plugin
 * Copyright (C) 2024 PQCA
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to you under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.ibm.mapper.mapper.bc;

import com.ibm.mapper.mapper.IMapper;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Padding;
import com.ibm.mapper.model.Unknown;
import com.ibm.mapper.model.padding.ANSIX923;
import com.ibm.mapper.model.padding.ISO10126;
import com.ibm.mapper.model.padding.ISO7816;
import com.ibm.mapper.model.padding.PKCS7;
import com.ibm.mapper.model.padding.TBC;
import com.ibm.mapper.model.padding.Zero;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class BcPaddingMapper implements IMapper {

    @Override
    @Nonnull
    public Optional<? extends INode> parse(
            @Nullable String str, @Nonnull DetectionLocation detectionLocation) {
        if (str == null) {
            return Optional.empty();
        }
        return map(str, detectionLocation);
    }

    @Nonnull
    private Optional<? extends INode> map(
            @Nonnull String blockCipherString, @Nonnull DetectionLocation detectionLocation) {
        return switch (blockCipherString) {
            case "ISO10126d2Padding" -> Optional.of(new ISO10126(detectionLocation));
            case "ISO7816d4Padding" -> Optional.of(new ISO7816(detectionLocation));
            case "PKCS7Padding" -> Optional.of(new PKCS7(detectionLocation));
            case "TBCPadding" -> Optional.of(new TBC(detectionLocation));
            case "X923Padding" -> Optional.of(new ANSIX923(detectionLocation));
            case "ZeroBytePadding" -> Optional.of(new Zero(detectionLocation));
            default -> {
                Padding padding = new Padding(blockCipherString, detectionLocation);
                padding.put(new Unknown(detectionLocation));
                yield Optional.of(padding);
            }
        };
    }
}

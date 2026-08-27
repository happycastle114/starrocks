// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package com.starrocks.mysql;

import com.google.common.collect.Maps;

import java.nio.ByteBuffer;
import java.util.Map;

// MySQL protocol change user packet, which contain authenticate information.
public class MysqlChangeUserPacket extends MysqlPacket {
    private int characterSet;
    private String userName;
    private byte[] authResponse;
    private String database;
    private String pluginName;
    private MysqlCapability capability;
    private Map<String, String> connectAttributes;

    public MysqlChangeUserPacket(MysqlCapability capability) {
        this.capability = capability;
    }

    public String getUser() {
        return userName;
    }

    public byte[] getAuthResponse() {
        return authResponse;
    }

    public String getDb() {
        return database;
    }

    public String getPluginName() {
        return pluginName;
    }

    public Map<String, String> getConnectAttributes() {
        return connectAttributes;
    }

    @Override
    public boolean readFrom(ByteBuffer buffer) {
        userName = null;
        authResponse = null;
        database = null;
        pluginName = null;
        connectAttributes = null;
        try {
            return readFromInternal(buffer);
        } catch (RuntimeException e) {
            return false;
        }
    }

    private boolean readFromInternal(ByteBuffer buffer) {
        // protocol refer to: https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_change_user.html
        if (buffer == null || capability == null || 2 > buffer.limit()
                || MysqlCommand.COM_CHANGE_USER.getCommandCode() != buffer.get(0)) {
            return false;
        }
        buffer.position(1);
        String parsedUserName = new String(MysqlCodec.readNulTerminateString(buffer));
        if (1 > buffer.remaining()) {
            return false;
        }
        // parse the password with the capability previously set on connecting
        byte[] parsedAuthResponse;
        if (capability.isSecureConnection()) {
            int len = MysqlCodec.readInt1(buffer);
            if (len > buffer.remaining()) {
                return false;
            }
            parsedAuthResponse = MysqlCodec.readFixedString(buffer, len);
        } else {
            parsedAuthResponse = MysqlCodec.readNulTerminateString(buffer);
        }
        // parse database name
        if (buffer.remaining() == 0) {
            return false;
        }
        String parsedDatabase = new String(MysqlCodec.readNulTerminateString(buffer));
        if (2 > buffer.remaining()) {
            return false;
        }
        int parsedCharacterSet = MysqlCodec.readInt2(buffer);
        // plugin name to plugin
        String parsedPluginName = null;
        if (0 < buffer.remaining() && capability.isPluginAuth()) {
            parsedPluginName = new String(MysqlCodec.readNulTerminateString(buffer));
        }
        // attribute map, no use now.
        Map<String, String> parsedConnectAttributes = null;
        if (0 < buffer.remaining() && capability.isConnectAttrs()) {
            long connectionAttributesLength = readCheckedVInt(buffer);
            if (connectionAttributesLength < 0 || connectionAttributesLength != buffer.remaining()) {
                return false;
            }
            parsedConnectAttributes = Maps.newHashMap();
            while (buffer.hasRemaining()) {
                String key = new String(readCheckedLenEncodedString(buffer));
                String value = new String(readCheckedLenEncodedString(buffer));
                parsedConnectAttributes.put(key, value);
            }
        }
        if (buffer.hasRemaining()) {
            return false;
        }

        userName = parsedUserName;
        authResponse = parsedAuthResponse;
        database = parsedDatabase;
        characterSet = parsedCharacterSet;
        pluginName = parsedPluginName;
        connectAttributes = parsedConnectAttributes;
        return true;
    }

    private static byte[] readCheckedLenEncodedString(ByteBuffer buffer) {
        long length = readCheckedVInt(buffer);
        if (length < 0 || length > Integer.MAX_VALUE || length > buffer.remaining()) {
            throw new IllegalArgumentException("Invalid length-encoded string");
        }
        return MysqlCodec.readFixedString(buffer, (int) length);
    }

    private static long readCheckedVInt(ByteBuffer buffer) {
        if (!buffer.hasRemaining()) {
            throw new IllegalArgumentException("Missing length-encoded integer");
        }
        int prefix = buffer.get(buffer.position()) & 0xFF;
        int encodedLength;
        if (prefix < 251) {
            encodedLength = 1;
        } else if (prefix == 252) {
            encodedLength = 3;
        } else if (prefix == 253) {
            encodedLength = 4;
        } else if (prefix == 254) {
            encodedLength = 9;
        } else {
            throw new IllegalArgumentException("Unsupported length-encoded integer prefix");
        }
        if (buffer.remaining() < encodedLength) {
            throw new IllegalArgumentException("Truncated length-encoded integer");
        }
        return MysqlCodec.readVInt(buffer);
    }

    @Override
    public void writeTo(MysqlSerializer serializer) {

    }
}

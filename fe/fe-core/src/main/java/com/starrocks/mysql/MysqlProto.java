// Copyright 2021-present StarRocks, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This file is based on code available under the Apache license here:
//   https://github.com/apache/incubator-doris/blob/master/fe/fe-core/src/main/java/org/apache/doris/mysql/MysqlProto.java

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

import com.google.common.base.Strings;
import com.starrocks.authentication.AuthenticationException;
import com.starrocks.authentication.AuthenticationHandler;
import com.starrocks.authentication.AuthenticationProvider;
import com.starrocks.authentication.AuthenticationProviderFactory;
import com.starrocks.authentication.OAuth2Context;
import com.starrocks.authentication.SecurityIntegration;
import com.starrocks.authentication.UserAuthenticationInfo;
import com.starrocks.common.Config;
import com.starrocks.common.ConfigBase;
import com.starrocks.common.ErrorCode;
import com.starrocks.common.ErrorReport;
import com.starrocks.common.Pair;
import com.starrocks.mysql.privilege.AuthPlugin;
import com.starrocks.mysql.ssl.SSLContextLoader;
import com.starrocks.qe.ConnectContext;
import com.starrocks.qe.ConnectScheduler;
import com.starrocks.qe.SessionVariable;
import com.starrocks.server.GlobalStateMgr;
import com.starrocks.service.ExecuteEnv;
import com.starrocks.sql.analyzer.Authorizer;
import com.starrocks.sql.ast.UserIdentity;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

// MySQL protocol util
public class MysqlProto {
    private static final Logger LOG = LogManager.getLogger(MysqlProto.class);

    private static final String LOCALHOST = "127.0.0.1";

    // send response packet(OK/EOF/ERR).
    // before call this function, should set information in state of ConnectContext
    public static void sendResponsePacket(ConnectContext context) throws IOException {
        MysqlSerializer serializer = context.getSerializer();
        MysqlChannel channel = context.getMysqlChannel();
        MysqlPacket packet = context.getState().toResponsePacket();

        // send response packet to client
        serializer.reset();
        packet.writeTo(serializer);
        channel.sendAndFlush(serializer.toByteBuffer());
    }

    /**
     * negotiate with client, use MySQL protocol
     * server ---handshake---> client
     * server <--- authenticate --- client
     * server --- response(OK/ERR) ---> client
     * Exception:
     * IOException:
     */
    public static NegotiateResult negotiate(ConnectContext context) throws IOException {
        MysqlSerializer serializer = context.getSerializer();
        MysqlChannel channel = context.getMysqlChannel();
        context.getState().setOk();

        // Server send handshake packet to client.
        serializer.reset();

        byte[] randomString = MysqlPassword.createRandomString();
        context.setAuthDataSalt(randomString);

        MysqlHandshakePacket handshakePacket = new MysqlHandshakePacket(context.getConnectionId(),
                SSLContextLoader.getSslContext() != null, randomString);
        handshakePacket.writeTo(serializer);
        channel.sendAndFlush(serializer.toByteBuffer());

        MysqlAuthPacket authPacket = readAuthPacket(context);
        if (authPacket == null) {
            return new NegotiateResult(null, NegotiateState.READ_FIRST_AUTH_PKG_FAILED);
        }

        if (authPacket.isSSLConnRequest()) {
            // change to ssl session
            LOG.info("start to enable ssl connection");
            if (!context.enableSSL()) {
                LOG.warn("enable ssl connection failed");
                ErrorReport.report(ErrorCode.ERR_CHANGE_TO_SSL_CONNECTION_FAILED);
                sendResponsePacket(context);
                return new NegotiateResult(authPacket, NegotiateState.ENABLE_SSL_FAILED);
            } else {
                LOG.info("enable ssl connection successfully");
            }

            // read the authentication package again from client
            authPacket = readAuthPacket(context);
            if (authPacket == null) {
                return new NegotiateResult(null, NegotiateState.READ_SSL_AUTH_PKG_FAILED);
            }
        } else if (Config.ssl_force_secure_transport) {
            if (!isRemoteIPLocalhost(context.getRemoteIP())) {
                LOG.warn("Connections using insecure transport are prohibited");
                ErrorReport.report(ErrorCode.ERR_SECURE_TRANSPORT_REQUIRED);
                sendResponsePacket(context);
                return new NegotiateResult(null, NegotiateState.INSECURE_TRANSPORT_PROHIBITED);
            } else {
                LOG.info("Connection made from a localhost, no secure transport enforced");
            }
        }

        // check capability
        if (!MysqlCapability.isCompatible(context.getServerCapability(), authPacket.getCapability())) {
            // TODO: client return capability can not support
            ErrorReport.report(ErrorCode.ERR_NOT_SUPPORTED_AUTH_MODE);
            sendResponsePacket(context);
            return new NegotiateResult(authPacket, NegotiateState.NOT_SUPPORTED_AUTH_MODE);
        }

        // StarRocks support the Protocol::AuthSwitchRequest to tell client which auth plugin is using
        try {
            switchAuthPlugin(authPacket, context);
        } catch (AuthenticationException e) {
            // receive response failed.
            LOG.warn("read auth switch response failed for user {}", authPacket.getUser());
            return new NegotiateResult(authPacket, NegotiateState.READ_AUTH_SWITCH_PKG_FAILED);
        }

        // Set the real user used for this connection.
        context.setQualifiedUser(authPacket.getUser());
        context.setAuthPlugin(authPacket.getPluginName());
        // change the capability of serializer
        context.setCapability(context.getServerCapability());
        serializer.setCapability(context.getCapability());

        return new NegotiateResult(authPacket, NegotiateState.OK);
    }

    public static NegotiateResult authenticate(ConnectContext context, MysqlAuthPacket authPacket) throws IOException {
        try {
            AuthenticationHandler.authenticate(context, authPacket.getUser(), context.getMysqlChannel().getRemoteIp(),
                    authPacket.getAuthResponse());
        } catch (AuthenticationException e) {
            if (e.getErrorCode() == null) {
                context.getState().setErrorCode(ErrorCode.ERR_AUTHENTICATION_FAIL);
                context.getState().setError(e.getMessage());
            } else {
                context.getState().setErrorCode(e.getErrorCode());
                context.getState().setError(e.getMessage());
            }

            sendResponsePacket(context);
            return new NegotiateResult(authPacket, NegotiateState.AUTHENTICATION_FAILED);
        }

        // set database
        String db = authPacket.getDb();
        if (!Strings.isNullOrEmpty(db)) {
            try {
                context.changeCatalogDb(db);
            } catch (Exception e) {
                LOG.warn("Set database [{}] failed during negotiate, user={}, reason={}",
                        db, authPacket.getUser(), e.getMessage(), e);
                if (!context.getState().isError()) {
                    context.getState().setError(e.getMessage());
                }
                sendResponsePacket(context);
                return new NegotiateResult(authPacket, NegotiateState.SET_DATABASE_FAILED);
            }
        }

        context.captureAuthenticatedIdentity();
        return new NegotiateResult(authPacket, NegotiateState.OK);
    }

    private static MysqlAuthPacket readAuthPacket(ConnectContext context) throws IOException {
        // Server receive authenticate packet from client.
        ByteBuffer handshakeResponse = context.getMysqlChannel().fetchOnePacket();
        if (handshakeResponse == null) {
            // receive response failed.
            return null;
        }
        MysqlAuthPacket authPacket = new MysqlAuthPacket();
        if (!authPacket.readFrom(handshakeResponse)) {
            ErrorReport.report(ErrorCode.ERR_NOT_SUPPORTED_AUTH_MODE);
            sendResponsePacket(context);
            return null;
        }
        return authPacket;
    }

    /**
     * Change user command use MySQL protocol
     * Exception:
     * IOException:
     */
    public static boolean changeUser(ConnectContext context, ByteBuffer buffer) throws IOException {
        // parse change user packet
        MysqlChangeUserPacket changeUserPacket = new MysqlChangeUserPacket(context.getCapability());
        if (!changeUserPacket.readFrom(buffer)) {
            context.getState().setErrorCode(ErrorCode.ERR_NOT_SUPPORTED_AUTH_MODE);
            context.getState().setError(ErrorCode.ERR_NOT_SUPPORTED_AUTH_MODE.formatErrorMsg());
            return false;
        }
        if (context.getTxnId() != 0) {
            context.getState().setErrorCode(ErrorCode.ERR_UNKNOWN_ERROR);
            context.getState().setError(
                    "COM_CHANGE_USER is not allowed while an explicit transaction is active");
            return false;
        }
        // save previous user login info
        AuthenticationState previousAuthenticationState = AuthenticationState.capture(context);
        String previousQualifiedUser = previousAuthenticationState.qualifiedUser();
        SessionVariable previousSessionVariable = (SessionVariable) context.getSessionVariable().clone();
        String previousCatalog = context.getCurrentCatalog();
        String previousDb = context.getDatabase();
        boolean previousWasRangerManaged;
        try {
            previousWasRangerManaged = Authorizer.isRangerManagedContext(context);
        } catch (RuntimeException e) {
            return rejectRangerManagedChangeUser(context, previousAuthenticationState,
                    previousSessionVariable, previousCatalog, previousDb,
                    previousQualifiedUser, changeUserPacket.getUser(), e);
        }
        // do authenticate again

        try {
            authenticateChangeUser(context, changeUserPacket);
        } catch (AuthenticationException e) {
            LOG.warn("Command `Change user` failed, from [{}] to [{}]. ", previousQualifiedUser,
                    changeUserPacket.getUser());
            restoreChangeUserState(context, previousAuthenticationState, previousSessionVariable,
                    previousCatalog, previousDb);
            setAuthenticationError(context, e);
            return false;
        } catch (RuntimeException e) {
            LOG.warn("Command `Change user` failed unexpectedly, from [{}] to [{}].",
                    previousQualifiedUser, changeUserPacket.getUser(), e);
            restoreChangeUserState(context, previousAuthenticationState, previousSessionVariable,
                    previousCatalog, previousDb);
            setAuthenticationError(context, authenticationFailure(changeUserPacket));
            return false;
        }
        try {
            if (previousWasRangerManaged || Authorizer.isRangerManagedContext(context)) {
                return rejectRangerManagedChangeUser(context, previousAuthenticationState,
                        previousSessionVariable, previousCatalog, previousDb,
                        previousQualifiedUser, changeUserPacket.getUser(), null);
            }
        } catch (RuntimeException e) {
            return rejectRangerManagedChangeUser(context, previousAuthenticationState,
                    previousSessionVariable, previousCatalog, previousDb,
                    previousQualifiedUser, changeUserPacket.getUser(), e);
        }
        // set database
        String db = changeUserPacket.getDb();
        if (!Strings.isNullOrEmpty(db)) {
            try {
                context.changeCatalogDb(db);
            } catch (Exception e) {
                LOG.warn("Command `Change user` failed at stage changing db, from [{}] to [{}], err[{}] ",
                        previousQualifiedUser, changeUserPacket.getUser(), e.getMessage(), e);
                restoreChangeUserState(context, previousAuthenticationState, previousSessionVariable,
                        previousCatalog, previousDb);
                if (!context.getState().isError()) {
                    context.getState().setError(e.getMessage());
                }
                return false;
            }
        }
        Pair<Boolean, String> userChangeResult;
        try {
            ConnectScheduler connectScheduler = ExecuteEnv.getInstance().getScheduler();
            userChangeResult = connectScheduler.onUserChanged(
                    context, previousQualifiedUser, context.getQualifiedUser());
        } catch (RuntimeException e) {
            LOG.warn("Command `Change user` failed at stage updating scheduler, from [{}] to [{}].",
                    previousQualifiedUser, changeUserPacket.getUser(), e);
            restoreChangeUserState(context, previousAuthenticationState, previousSessionVariable,
                    previousCatalog, previousDb);
            context.getState().setErrorCode(ErrorCode.ERR_UNKNOWN_ERROR);
            context.getState().setError("Failed to change user");
            return false;
        }
        if (!userChangeResult.first) {
            restoreChangeUserState(context, previousAuthenticationState, previousSessionVariable,
                    previousCatalog, previousDb);
            context.getState().setErrorCode(ErrorCode.ERR_TOO_MANY_USER_CONNECTIONS);
            context.getState().setError(userChangeResult.second);
            return false;
        }

        context.captureAuthenticatedIdentity();
        LOG.info("Command `Change user` succeeded, from [{}] to [{}]. ", previousQualifiedUser,
                context.getQualifiedUser());
        return true;
    }

    private static void authenticateChangeUser(ConnectContext context, MysqlChangeUserPacket changeUserPacket)
            throws AuthenticationException {
        String remoteIp = context.getMysqlChannel().getRemoteIp();
        ChangeUserTarget initialTarget = ChangeUserTarget.capture(GlobalStateMgr.getCurrentState()
                .getAuthenticationMgr().getBestMatchedUserIdentity(changeUserPacket.getUser(), remoteIp));
        if (!isSupportedChangeUserTarget(initialTarget, changeUserPacket)) {
            throw authenticationFailure(changeUserPacket);
        }

        String serverPlugin = initialTarget.serverPlugin();
        String clientPlugin = AuthPlugin.covertFromServerToClient(serverPlugin);
        String packetPlugin = changeUserPacket.getPluginName();
        if (packetPlugin == null) {
            if (!AuthPlugin.Client.MYSQL_NATIVE_PASSWORD.toString().equalsIgnoreCase(clientPlugin)) {
                throw authenticationFailure(changeUserPacket);
            }
        } else if (!clientPlugin.equalsIgnoreCase(packetPlugin)) {
            throw authenticationFailure(changeUserPacket);
        }

        clearAuthenticationStateForChangeUser(context, clientPlugin);
        UserIdentity authenticatedUser = AuthenticationHandler.authenticate(
                context, changeUserPacket.getUser(), remoteIp, changeUserPacket.getAuthResponse());
        ChangeUserTarget currentTarget = ChangeUserTarget.capture(GlobalStateMgr.getCurrentState()
                .getAuthenticationMgr().getBestMatchedUserIdentity(changeUserPacket.getUser(), remoteIp));
        if (!isSameLocalTarget(initialTarget, currentTarget, authenticatedUser, context, clientPlugin)) {
            throw authenticationFailure(changeUserPacket);
        }
    }

    private static boolean isSupportedChangeUserTarget(
            ChangeUserTarget target, MysqlChangeUserPacket changeUserPacket) {
        if (target == null || target.userIdentity().isEphemeral() || target.serverPlugin() == null) {
            return false;
        }
        String serverPlugin = target.serverPlugin();
        if (AuthPlugin.Server.AUTHENTICATION_OAUTH2.toString().equalsIgnoreCase(serverPlugin)) {
            return false;
        }
        String clientPlugin = AuthPlugin.covertFromServerToClient(serverPlugin);
        return clientPlugin != null && changeUserPacket.getAuthResponse() != null;
    }

    private static boolean isSameLocalTarget(
            ChangeUserTarget initialTarget, ChangeUserTarget currentTarget,
            UserIdentity authenticatedUser, ConnectContext context, String clientPlugin) {
        UserIdentity contextUser = context.getCurrentUserIdentity();
        return currentTarget != null
                && !currentTarget.userIdentity().isEphemeral()
                && currentTarget.userIdentity().equals(initialTarget.userIdentity())
                && currentTarget.hasSameAuthentication(initialTarget)
                && clientPlugin.equalsIgnoreCase(AuthPlugin.covertFromServerToClient(currentTarget.serverPlugin()))
                && authenticatedUser != null
                && !authenticatedUser.isEphemeral()
                && authenticatedUser.equals(initialTarget.userIdentity())
                && contextUser != null
                && !contextUser.isEphemeral()
                && contextUser.equals(initialTarget.userIdentity())
                && initialTarget.userIdentity().getUser().equals(context.getQualifiedUser())
                && ConfigBase.AUTHENTICATION_CHAIN_MECHANISM_NATIVE.equals(context.getSecurityIntegration())
                && clientPlugin.equalsIgnoreCase(context.getAuthPlugin());
    }

    private record ChangeUserTarget(
            UserIdentity userIdentity, String serverPlugin, byte[] password, String authString) {
        private static ChangeUserTarget capture(Map.Entry<UserIdentity, UserAuthenticationInfo> target) {
            if (target == null) {
                return null;
            }
            UserAuthenticationInfo authenticationInfo = target.getValue();
            byte[] password = authenticationInfo.getPassword();
            return new ChangeUserTarget(
                    target.getKey(), authenticationInfo.getAuthPlugin(),
                    password == null ? null : Arrays.copyOf(password, password.length),
                    authenticationInfo.getAuthString());
        }

        private boolean hasSameAuthentication(ChangeUserTarget other) {
            return serverPlugin != null
                    && other != null
                    && other.serverPlugin != null
                    && serverPlugin.equalsIgnoreCase(other.serverPlugin)
                    && Arrays.equals(password, other.password)
                    && Objects.equals(authString, other.authString);
        }
    }

    private static void clearAuthenticationStateForChangeUser(ConnectContext context, String clientPlugin) {
        context.setCurrentUserIdentity(null);
        context.setQualifiedUser(null);
        context.setCurrentRoleIds((Set<Long>) null);
        context.setGroups(null);
        context.setSecurityIntegration(null);
        context.setDistinguishedName("");
        context.setAuthToken(null);
        context.setOAuth2Context(null);
        context.setAuthPlugin(clientPlugin);
    }

    private static AuthenticationException authenticationFailure(MysqlChangeUserPacket changeUserPacket) {
        byte[] authResponse = changeUserPacket.getAuthResponse();
        String usePassword = authResponse == null || authResponse.length == 0 ? "NO" : "YES";
        return new AuthenticationException(ErrorCode.ERR_AUTHENTICATION_FAIL,
                changeUserPacket.getUser(), usePassword);
    }

    private static void setAuthenticationError(ConnectContext context, AuthenticationException exception) {
        ErrorCode errorCode = exception.getErrorCode() == null
                ? ErrorCode.ERR_AUTHENTICATION_FAIL : exception.getErrorCode();
        context.getState().setErrorCode(errorCode);
        context.getState().setError(exception.getMessage());
    }

    private static boolean rejectRangerManagedChangeUser(
            ConnectContext context, AuthenticationState previousAuthenticationState,
            SessionVariable previousSessionVariable, String previousCatalog, String previousDb,
            String previousUser, String targetUser, RuntimeException cause) throws IOException {
        LOG.warn("Command `Change user` denied at Ranger-managed identity boundary, from [{}] to [{}].",
                previousUser, targetUser, cause);
        restoreChangeUserState(context, previousAuthenticationState, previousSessionVariable,
                previousCatalog, previousDb);
        context.getState().setErrorCode(ErrorCode.ERR_ACCESS_DENIED_FOR_EXTERNAL_ACCESS_CONTROLLER);
        context.getState().setError("COM_CHANGE_USER is not allowed for Ranger-managed users");
        return false;
    }

    private static void restoreChangeUserState(
            ConnectContext context, AuthenticationState previousAuthenticationState,
            SessionVariable previousSessionVariable, String previousCatalog, String previousDb) {
        previousAuthenticationState.restore(context);
        context.setSessionVariable(previousSessionVariable);
        context.setCurrentCatalog(previousCatalog);
        context.setDatabase(previousDb);
    }

    private record AuthenticationState(UserIdentity currentUserIdentity, String qualifiedUser, Set<Long> currentRoleIds,
                                       Set<String> groups, String securityIntegration, String distinguishedName,
                                       String authToken, OAuth2Context oAuth2Context, String authPlugin) {
        private static AuthenticationState capture(ConnectContext context) {
            return new AuthenticationState(
                    context.getCurrentUserIdentity(), context.getQualifiedUser(),
                    copySet(context.getCurrentRoleIds()), copySet(context.getGroups()),
                    context.getSecurityIntegration(), context.getDistinguishedName(),
                    context.getAuthToken(), context.getOAuth2Context(), context.getAuthPlugin());
        }

        private void restore(ConnectContext context) {
            context.setCurrentUserIdentity(currentUserIdentity);
            context.setQualifiedUser(qualifiedUser);
            context.setCurrentRoleIds(copySet(currentRoleIds));
            context.setGroups(copySet(groups));
            context.setSecurityIntegration(securityIntegration);
            context.setDistinguishedName(distinguishedName);
            context.setAuthToken(authToken);
            context.setOAuth2Context(oAuth2Context);
            context.setAuthPlugin(authPlugin);
        }

        private static <T> Set<T> copySet(Set<T> values) {
            return values == null ? null : new HashSet<>(values);
        }
    }

    public static boolean isRemoteIPLocalhost(String remoteIP) {
        if (remoteIP == null) {
            return false;
        }
        //Using "String.contains" here because the remote IP address starts with a forward slash, like “/127.0.0.1”.
        return remoteIP.contains(LOCALHOST);
    }

    public record NegotiateResult(MysqlAuthPacket authPacket, NegotiateState state) {
    }

    public static void switchAuthPlugin(MysqlAuthPacket mysqlAuthPacket, ConnectContext context)
            throws AuthenticationException, IOException {
        String user = mysqlAuthPacket.getUser();
        String authPluginName = mysqlAuthPacket.getPluginName();

        // Older version mysql client does not send auth plugin info, like 5.1 version.
        if (authPluginName == null) {
            return;
        }

        String switchAuthPlugin = null;
        AuthenticationProvider provider = null;

        Map.Entry<UserIdentity, UserAuthenticationInfo> localUser = GlobalStateMgr.getCurrentState().getAuthenticationMgr()
                .getBestMatchedUserIdentity(user, context.getMysqlChannel().getRemoteIp());
        if (localUser != null) {
            UserAuthenticationInfo authInfo = localUser.getValue();
            switchAuthPlugin = AuthPlugin.covertFromServerToClient(authInfo.getAuthPlugin());
            provider = AuthenticationProviderFactory.create(authInfo.getAuthPlugin(), authInfo.getAuthString());
        } else {
            for (String authMechanism : Config.authentication_chain) {
                if (authMechanism.equals(ConfigBase.AUTHENTICATION_CHAIN_MECHANISM_NATIVE)) {
                    continue;
                }

                //Because we only support Security Integration of the same type, we use the first non-Native type here.
                SecurityIntegration securityIntegration =
                        GlobalStateMgr.getCurrentState().getAuthenticationMgr().getSecurityIntegration(authMechanism);
                switchAuthPlugin = AuthPlugin.covertFromServerToClient(securityIntegration.getType());
                provider = securityIntegration.getAuthenticationProvider();
                break;
            }
        }

        if (provider == null) {
            return;
        }

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        if (!authPluginName.equalsIgnoreCase(switchAuthPlugin)) {
            // AuthSwitchRequest Packet
            MysqlCodec.writeInt1(outputStream, (byte) 0xfe);
            MysqlCodec.writeNulTerminateString(outputStream, switchAuthPlugin);

            byte[] authSwitchRequestPacket =
                    provider.authSwitchRequestPacket(context, user, context.getMysqlChannel().getRemoteIp());
            if (authSwitchRequestPacket != null) {
                MysqlCodec.writeBytes(outputStream, authSwitchRequestPacket);
            }
            MysqlCodec.writeInt1(outputStream, 0);
        } else {
            // AuthMoreData Packet
            byte[] authMoreDataPacket = provider.authMoreDataPacket(context, user, context.getMysqlChannel().getRemoteIp());
            if (authMoreDataPacket != null) {
                MysqlCodec.writeInt1(outputStream, (byte) 0x01);
                MysqlCodec.writeBytes(outputStream, authMoreDataPacket);
            }
        }

        // mysql client may not support starrocks custom plugin, so it does not send a switch packet.
        if (!authPluginName.equalsIgnoreCase(switchAuthPlugin) && AuthPlugin.isStarRocksCustomAuthPlugin(switchAuthPlugin)) {
            return;
        }

        if (outputStream.size() > 0) {
            MysqlChannel channel = context.getMysqlChannel();
            channel.sendAndFlush(ByteBuffer.wrap(outputStream.toByteArray()));
            ByteBuffer authSwitchResponse = channel.fetchOnePacket();
            if (authSwitchResponse == null) {
                throw new AuthenticationException("read auth switch response failed for user " + user);
            }
            mysqlAuthPacket.setPluginName(switchAuthPlugin);
            mysqlAuthPacket.setAuthResponse(MysqlCodec.readEofString(authSwitchResponse));
        }
    }
}

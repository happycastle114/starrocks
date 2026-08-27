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

package com.starrocks.mysql;

import com.starrocks.authentication.AuthenticationException;
import com.starrocks.authentication.AuthenticationHandler;
import com.starrocks.authentication.AuthenticationMgr;
import com.starrocks.authentication.OAuth2Context;
import com.starrocks.authentication.UserAuthenticationInfo;
import com.starrocks.authorization.AccessDeniedException;
import com.starrocks.authorization.MockedLocalMetaStore;
import com.starrocks.authorization.RBACMockedMetadataMgr;
import com.starrocks.common.ErrorCode;
import com.starrocks.common.Pair;
import com.starrocks.mysql.privilege.AuthPlugin;
import com.starrocks.persist.EditLog;
import com.starrocks.qe.ConnectContext;
import com.starrocks.qe.ConnectScheduler;
import com.starrocks.server.GlobalStateMgr;
import com.starrocks.service.ExecuteEnv;
import com.starrocks.sql.analyzer.Analyzer;
import com.starrocks.sql.analyzer.Authorizer;
import com.starrocks.sql.ast.CreateUserStmt;
import com.starrocks.sql.ast.UserIdentity;
import com.starrocks.sql.parser.SqlParser;
import com.starrocks.utframe.UtFrameUtils;
import mockit.Mock;
import mockit.MockUp;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyShort;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.spy;

/**
 * Test cases for MysqlProto.changeUser function
 * This test covers various scenarios including successful user changes,
 * authentication failures, database switching, and error recovery.
 */
public class MysqlProtoChangeUserTest {
    private static final String MANAGED_USER = "flight_sql_ci";
    private static final String JWT_USER = "jwt_user";
    private static final String OAUTH2_USER = "oauth2_user";
    private static final String ORIGINAL_AUTH_TOKEN = "original-auth-token";
    private static final String TARGET_AUTH_TOKEN = "target-auth-token";
    private static final String ORIGINAL_AUTH_PLUGIN = "original-auth-plugin";
    private static final OAuth2Context ORIGINAL_OAUTH2_CONTEXT = createOAuth2Context("original");
    private static final OAuth2Context TARGET_OAUTH2_CONTEXT = createOAuth2Context("target");

    private ConnectContext context;
    private AuthenticationMgr authMgr;

    @BeforeEach
    public void setUp() throws Exception {
        // Mock EditLog to prevent NullPointerException
        EditLog editLog = spy(new EditLog(null));
        doNothing().when(editLog).logEdit(anyShort(), any());
        GlobalStateMgr.getCurrentState().setEditLog(editLog);
        
        // Initialize test context
        context = UtFrameUtils.initCtxForNewPrivilege(UserIdentity.ROOT);
        context.setQualifiedUser("root");
        context.setCurrentUserIdentity(UserIdentity.ROOT);
        context.setDatabase("test_db");
        context.setCapability(MysqlCapability.DEFAULT_CAPABILITY);
        
        // Mock MysqlChannel
        new MockUp<MysqlChannel>() {
            @Mock
            public void sendAndFlush(ByteBuffer packet) throws IOException {
                // Mock send operation - do nothing for testing
            }
            
            @Mock
            public String getRemoteIp() {
                return "127.0.0.1";
            }
        };
        
        // Initialize authentication manager
        authMgr = new AuthenticationMgr();
        GlobalStateMgr.getCurrentState().setAuthenticationMgr(authMgr);
        
        // Create test users
        createTestUsers();
    }

    private void createTestUsers() throws Exception {
        // Create user1 with password
        CreateUserStmt createUser1 = (CreateUserStmt) SqlParser
                .parse("create user user1 identified with mysql_native_password by 'password1'", 32).get(0);
        Analyzer.analyze(createUser1, context);
        authMgr.createUser(createUser1);
        
        // Create user2 with password
        CreateUserStmt createUser2 = (CreateUserStmt) SqlParser
                .parse("create user user2 identified with mysql_native_password by 'password2'", 32).get(0);
        Analyzer.analyze(createUser2, context);
        authMgr.createUser(createUser2);
        
        // Create user3 with empty password
        CreateUserStmt createUser3 = (CreateUserStmt) SqlParser
                .parse("create user user3 identified with mysql_native_password by ''", 32).get(0);
        Analyzer.analyze(createUser3, context);
        authMgr.createUser(createUser3);

        CreateUserStmt createManagedUser = (CreateUserStmt) SqlParser
                .parse("create user " + MANAGED_USER +
                        " identified with mysql_native_password by 'managed_password'", 32).get(0);
        Analyzer.analyze(createManagedUser, context);
        authMgr.createUser(createManagedUser);

        CreateUserStmt createJwtUser = (CreateUserStmt) SqlParser
                .parse("create user " + JWT_USER + " identified with authentication_jwt", 32).get(0);
        Analyzer.analyze(createJwtUser, context);
        authMgr.createUser(createJwtUser);

        CreateUserStmt createOAuth2User = (CreateUserStmt) SqlParser
                .parse("create user " + OAUTH2_USER + " identified with authentication_oauth2", 32).get(0);
        Analyzer.analyze(createOAuth2User, context);
        authMgr.createUser(createOAuth2User);
    }

    /**
     * Test change user with invalid packet format
     */
    @Test
    public void testChangeUserInvalidPacket() throws IOException {
        AuthenticationStateSnapshot previousState = AuthenticationStateSnapshot.capture(context);
        ByteBuffer truncatedUser = ByteBuffer.wrap(new byte[] {
                (byte) MysqlCommand.COM_CHANGE_USER.getCommandCode(), 'u'
        });

        Assertions.assertFalse(MysqlProto.changeUser(context, truncatedUser));
        previousState.assertRestored(context);
        Assertions.assertEquals(ErrorCode.ERR_NOT_SUPPORTED_AUTH_MODE, context.getState().getErrorCode());
    }

    @Test
    public void testChangeUserPacketSecureAuthResponseUsesOneByteLengthAtBoundaries() {
        Assertions.assertTrue(MysqlCapability.DEFAULT_CAPABILITY.isPluginAuthDataLengthEncoded());
        for (int authResponseLength : new int[] {250, 251, 255}) {
            byte[] authResponse = new byte[authResponseLength];
            Arrays.fill(authResponse, (byte) 1);
            ByteBuffer buffer = createChangeUserPacket(
                    "user1", authResponse, null, AuthPlugin.Client.MYSQL_NATIVE_PASSWORD.toString());
            MysqlChangeUserPacket packet = new MysqlChangeUserPacket(MysqlCapability.DEFAULT_CAPABILITY);

            Assertions.assertTrue(packet.readFrom(buffer), "length=" + authResponseLength);
            Assertions.assertArrayEquals(authResponse, packet.getAuthResponse(), "length=" + authResponseLength);
        }
    }

    @Test
    public void testChangeUserPacketRejectsTruncatedSecureAuthResponse() {
        MysqlSerializer serializer = MysqlSerializer.newInstance();
        serializer.writeInt1(MysqlCommand.COM_CHANGE_USER.getCommandCode());
        serializer.writeNulTerminateString("user1");
        serializer.writeInt1(255);
        serializer.writeBytes(new byte[254]);

        MysqlChangeUserPacket packet = new MysqlChangeUserPacket(MysqlCapability.DEFAULT_CAPABILITY);
        Assertions.assertFalse(packet.readFrom(serializer.toByteBuffer()));
    }

    @Test
    public void testChangeUserPacketRejectsMalformedTrailingFields() {
        MysqlSerializer missingDatabaseTerminator = createChangeUserPacketPrefix();
        missingDatabaseTerminator.writeEofString("db");
        assertMalformedChangeUserPacket(missingDatabaseTerminator, "database terminator");

        MysqlSerializer truncatedCharacterSet = createChangeUserPacketPrefix();
        truncatedCharacterSet.writeNulTerminateString("db");
        truncatedCharacterSet.writeInt1(33);
        assertMalformedChangeUserPacket(truncatedCharacterSet, "character set");

        MysqlSerializer missingPluginTerminator = createChangeUserPacketThroughCharacterSet();
        missingPluginTerminator.writeEofString(AuthPlugin.Client.MYSQL_NATIVE_PASSWORD.toString());
        assertMalformedChangeUserPacket(missingPluginTerminator, "plugin terminator");

        MysqlSerializer unsupportedAttributeLength = createChangeUserPacketThroughPlugin();
        unsupportedAttributeLength.writeInt1(255);
        assertMalformedChangeUserPacket(unsupportedAttributeLength, "attribute length prefix");

        MysqlSerializer unsupportedAttributeKeyLength = createChangeUserPacketThroughPlugin();
        unsupportedAttributeKeyLength.writeInt1(2);
        unsupportedAttributeKeyLength.writeInt1(255);
        unsupportedAttributeKeyLength.writeInt1(0);
        assertMalformedChangeUserPacket(unsupportedAttributeKeyLength, "attribute key length prefix");

        MysqlSerializer truncatedAttributePair = createChangeUserPacketThroughPlugin();
        truncatedAttributePair.writeInt1(1);
        truncatedAttributePair.writeInt1(0);
        assertMalformedChangeUserPacket(truncatedAttributePair, "attribute pair");

        MysqlSerializer trailingData = createChangeUserPacketThroughPlugin();
        trailingData.writeInt1(0);
        trailingData.writeInt1(0);
        assertMalformedChangeUserPacket(trailingData, "trailing data");
    }

    @Test
    public void testChangeUserPacketAcceptsFullyConsumedConnectAttributes() {
        MysqlSerializer serializer = createChangeUserPacketThroughPlugin();
        serializer.writeInt1(4);
        serializer.writeInt1(1);
        serializer.writeInt1('k');
        serializer.writeInt1(1);
        serializer.writeInt1('v');
        MysqlChangeUserPacket packet = new MysqlChangeUserPacket(MysqlCapability.DEFAULT_CAPABILITY);

        Assertions.assertTrue(packet.readFrom(serializer.toByteBuffer()));
        Assertions.assertEquals(Map.of("k", "v"), packet.getConnectAttributes());
    }

    @Test
    public void testChangeUserRejectsMissingEmptyOrMismatchedTargetPlugin() throws IOException {
        AuthenticationStateSnapshot previousState = setDistinctAuthenticationState();
        byte[] authResponse = "jwt-token".getBytes(StandardCharsets.UTF_8);

        try (MockedStatic<AuthenticationHandler> authentication = Mockito.mockStatic(AuthenticationHandler.class)) {
            for (String pluginName : new String[] {
                    null, "", AuthPlugin.Client.MYSQL_NATIVE_PASSWORD.toString()
            }) {
                context.getState().reset();
                ByteBuffer changeUserPacket = createChangeUserPacket(
                        JWT_USER, authResponse, null, pluginName);

                Assertions.assertFalse(MysqlProto.changeUser(context, changeUserPacket));
                previousState.assertRestored(context);
                Assertions.assertEquals(ErrorCode.ERR_AUTHENTICATION_FAIL, context.getState().getErrorCode());
            }
            authentication.verifyNoInteractions();
        }
    }

    @Test
    public void testChangeUserRejectsOAuth2TargetWithoutReusingSourceToken() throws IOException {
        AuthenticationStateSnapshot previousState = setDistinctAuthenticationState();
        ByteBuffer changeUserPacket = createChangeUserPacket(
                OAUTH2_USER, "oauth-response".getBytes(StandardCharsets.UTF_8), null,
                AuthPlugin.Client.AUTHENTICATION_OAUTH2_CLIENT.toString());

        try (MockedStatic<AuthenticationHandler> authentication = Mockito.mockStatic(AuthenticationHandler.class)) {
            Assertions.assertFalse(MysqlProto.changeUser(context, changeUserPacket));
            authentication.verifyNoInteractions();
        }

        previousState.assertRestored(context);
        Assertions.assertEquals(ORIGINAL_AUTH_TOKEN, context.getAuthToken());
        Assertions.assertSame(ORIGINAL_OAUTH2_CONTEXT, context.getOAuth2Context());
        Assertions.assertEquals(ErrorCode.ERR_AUTHENTICATION_FAIL, context.getState().getErrorCode());
    }

    @Test
    public void testChangeUserRejectsActiveExplicitTransactionWithoutChangingSourceState() throws IOException {
        AuthenticationStateSnapshot previousState = setDistinctAuthenticationState();
        context.setTxnId(1234L);
        ByteBuffer changeUserPacket = createChangeUserPacket("user1", "password1", null);

        try (MockedStatic<AuthenticationHandler> authentication = Mockito.mockStatic(AuthenticationHandler.class)) {
            Assertions.assertFalse(MysqlProto.changeUser(context, changeUserPacket));
            authentication.verifyNoInteractions();
        }

        previousState.assertRestored(context);
        Assertions.assertEquals(1234L, context.getTxnId());
        Assertions.assertEquals(ErrorCode.ERR_UNKNOWN_ERROR, context.getState().getErrorCode());
    }

    /**
     * Test change user with authentication failure
     */
    @Test
    public void testChangeUserAuthenticationFailure() throws IOException {
        // Create change user packet with wrong password
        ByteBuffer changeUserPacket = createChangeUserPacket("user1", "wrong_password", "new_db");
        
        // Save original user info for verification
        String originalUser = context.getQualifiedUser();
        String originalDb = context.getDatabase();
        UserIdentity originalUserIdentity = context.getCurrentUserIdentity();
        
        // Execute change user
        boolean result = MysqlProto.changeUser(context, changeUserPacket);
        
        // Verify failure and rollback
        Assertions.assertFalse(result, "Change user should fail with wrong password");
        Assertions.assertEquals(originalUser, context.getQualifiedUser());
        Assertions.assertEquals(originalDb, context.getDatabase());
        Assertions.assertEquals(originalUserIdentity, context.getCurrentUserIdentity());
    }

    @Test
    public void testChangeUserAuthenticationFailureRestoresCompleteState() throws IOException {
        AuthenticationStateSnapshot previousState = setDistinctAuthenticationState();
        context.getSessionVariable().setResourceGroup("original-resource-group");
        ByteBuffer changeUserPacket = createChangeUserPacket("user1", "password1", null);

        try (MockedStatic<AuthenticationHandler> authentication = Mockito.mockStatic(AuthenticationHandler.class)) {
            authentication.when(() -> AuthenticationHandler.authenticate(
                            any(ConnectContext.class), any(String.class), any(String.class), any(byte[].class)))
                    .thenAnswer(invocation -> {
                        mutateAuthenticationState(context);
                        context.getSessionVariable().setResourceGroup("changed-resource-group");
                        throw new AuthenticationException("authentication failed after partial context update");
                    });

            Assertions.assertFalse(MysqlProto.changeUser(context, changeUserPacket));
        }

        previousState.assertRestored(context);
        Assertions.assertEquals("original-resource-group", context.getSessionVariable().getResourceGroup());
    }

    @Test
    public void testChangeUserAuthenticationFailureRestoresNullState() throws IOException {
        context.setCurrentUserIdentity(null);
        context.setQualifiedUser(null);
        context.setCurrentRoleIds((Set<Long>) null);
        context.setGroups(null);
        context.setSecurityIntegration(null);
        context.setDistinguishedName(null);
        context.setAuthToken(null);
        context.setOAuth2Context(null);
        context.setAuthPlugin(null);
        AuthenticationStateSnapshot previousState = AuthenticationStateSnapshot.capture(context);
        ByteBuffer changeUserPacket = createChangeUserPacket("user1", "password1", null);

        try (MockedStatic<AuthenticationHandler> authentication = Mockito.mockStatic(AuthenticationHandler.class)) {
            authentication.when(() -> AuthenticationHandler.authenticate(
                            any(ConnectContext.class), any(String.class), any(String.class), any(byte[].class)))
                    .thenAnswer(invocation -> {
                        mutateAuthenticationState(context);
                        throw new AuthenticationException("authentication failed after partial context update");
                    });

            Assertions.assertFalse(MysqlProto.changeUser(context, changeUserPacket));
        }

        previousState.assertRestored(context);
    }

    @Test
    public void testChangeUserFromRangerManagedUserIsDeniedAndRestored() throws Exception {
        context.setQualifiedUser(MANAGED_USER);
        context.setCurrentUserIdentity(new UserIdentity(MANAGED_USER, "%"));
        AuthenticationStateSnapshot previousState = setDistinctAuthenticationState();
        context.getSessionVariable().setResourceGroup("managed-resource-group");
        context.getSessionVariable().setQueryTimeoutS(37);
        authMgr.updateUserProperty("user1", List.of(Pair.create("session.query_timeout", "123")));
        ByteBuffer changeUserPacket = createChangeUserPacket("user1", "password1", null);

        try (MockedStatic<Authorizer> authorizer = Mockito.mockStatic(Authorizer.class)) {
            authorizer.when(() -> Authorizer.isRangerManagedContext(context))
                    .thenAnswer(invocation -> MANAGED_USER.equals(context.getQualifiedUser()));

            Assertions.assertFalse(MysqlProto.changeUser(context, changeUserPacket));
        }

        previousState.assertRestored(context);
        Assertions.assertEquals("managed-resource-group", context.getSessionVariable().getResourceGroup());
        Assertions.assertEquals(37, context.getSessionVariable().getQueryTimeoutS());
        Assertions.assertEquals(ErrorCode.ERR_ACCESS_DENIED_FOR_EXTERNAL_ACCESS_CONTROLLER,
                context.getState().getErrorCode());
    }

    @Test
    public void testChangeUserToRangerManagedUserIsDeniedAndRestored() throws Exception {
        AuthenticationStateSnapshot previousState = setDistinctAuthenticationState();
        context.getSessionVariable().setResourceGroup("ordinary-resource-group");
        context.getSessionVariable().setQueryTimeoutS(41);
        ByteBuffer changeUserPacket = createChangeUserPacket(MANAGED_USER, "managed_password", null);

        try (MockedStatic<AuthenticationHandler> authentication = Mockito.mockStatic(AuthenticationHandler.class);
                MockedStatic<Authorizer> authorizer = Mockito.mockStatic(Authorizer.class)) {
            authentication.when(() -> AuthenticationHandler.authenticate(
                            any(ConnectContext.class), any(String.class), any(String.class), any(byte[].class)))
                    .thenAnswer(invocation -> {
                        installAuthenticatedTarget(context, MANAGED_USER,
                                AuthPlugin.Client.MYSQL_NATIVE_PASSWORD.toString(), TARGET_AUTH_TOKEN);
                        context.getSessionVariable().setResourceGroup("target-resource-group");
                        context.getSessionVariable().setQueryTimeoutS(321);
                        return context.getCurrentUserIdentity();
                    });
            authorizer.when(() -> Authorizer.isRangerManagedContext(context))
                    .thenAnswer(invocation -> MANAGED_USER.equals(context.getQualifiedUser()));

            Assertions.assertFalse(MysqlProto.changeUser(context, changeUserPacket));
        }

        previousState.assertRestored(context);
        Assertions.assertEquals("ordinary-resource-group", context.getSessionVariable().getResourceGroup());
        Assertions.assertEquals(41, context.getSessionVariable().getQueryTimeoutS());
        Assertions.assertEquals(ErrorCode.ERR_ACCESS_DENIED_FOR_EXTERNAL_ACCESS_CONTROLLER,
                context.getState().getErrorCode());
    }

    @Test
    public void testChangeUserSuccessRetainsTargetAuthenticationState() throws IOException {
        setDistinctAuthenticationState();
        String targetPlugin = AuthPlugin.Client.AUTHENTICATION_OPENID_CONNECT_CLIENT.toString();
        ByteBuffer changeUserPacket = createChangeUserPacket(
                JWT_USER, "jwt-token".getBytes(StandardCharsets.UTF_8), null, targetPlugin);

        new MockUp<ConnectScheduler>() {
            @Mock
            public Pair<Boolean, String> onUserChanged(
                    ConnectContext context, String previousUser, String newUser) {
                return Pair.create(true, "");
            }
        };
        new MockUp<ExecuteEnv>() {
            @Mock
            public ConnectScheduler getScheduler() {
                return new ConnectScheduler(1000);
            }
        };

        try (MockedStatic<AuthenticationHandler> authentication = Mockito.mockStatic(AuthenticationHandler.class);
                MockedStatic<Authorizer> authorizer = Mockito.mockStatic(Authorizer.class)) {
            authentication.when(() -> AuthenticationHandler.authenticate(
                            any(ConnectContext.class), any(String.class), any(String.class), any(byte[].class)))
                    .thenAnswer(invocation -> {
                        Assertions.assertNull(context.getCurrentUserIdentity());
                        Assertions.assertNull(context.getQualifiedUser());
                        Assertions.assertNull(context.getCurrentRoleIds());
                        Assertions.assertNull(context.getGroups());
                        Assertions.assertNull(context.getSecurityIntegration());
                        Assertions.assertEquals("", context.getDistinguishedName());
                        Assertions.assertNull(context.getAuthToken());
                        Assertions.assertNull(context.getOAuth2Context());
                        Assertions.assertEquals(targetPlugin, context.getAuthPlugin());
                        return installAuthenticatedTarget(context, JWT_USER, targetPlugin, TARGET_AUTH_TOKEN);
                    });
            authorizer.when(() -> Authorizer.isRangerManagedContext(context)).thenReturn(false);

            Assertions.assertTrue(MysqlProto.changeUser(context, changeUserPacket));
        }

        Assertions.assertEquals(JWT_USER, context.getQualifiedUser());
        Assertions.assertEquals(
                authMgr.getBestMatchedUserIdentity(JWT_USER, "127.0.0.1").getKey(),
                context.getCurrentUserIdentity());
        Assertions.assertEquals(context.getCurrentUserIdentity(), context.getAuthenticatedUserIdentity());
        Assertions.assertEquals(TARGET_AUTH_TOKEN, context.getAuthToken());
        Assertions.assertNull(context.getOAuth2Context());
        Assertions.assertEquals(targetPlugin, context.getAuthPlugin());
    }

    @Test
    public void testChangeUserRejectsConcurrentTargetPluginChange() throws Exception {
        AuthenticationStateSnapshot previousState = setDistinctAuthenticationState();
        String targetPlugin = AuthPlugin.Client.AUTHENTICATION_OPENID_CONNECT_CLIENT.toString();
        ByteBuffer changeUserPacket = createChangeUserPacket(
                JWT_USER, "jwt-token".getBytes(StandardCharsets.UTF_8), null, targetPlugin);

        try (MockedStatic<AuthenticationHandler> authentication = Mockito.mockStatic(AuthenticationHandler.class);
                MockedStatic<Authorizer> authorizer = Mockito.mockStatic(Authorizer.class)) {
            authentication.when(() -> AuthenticationHandler.authenticate(
                            any(ConnectContext.class), any(String.class), any(String.class), any(byte[].class)))
                    .thenAnswer(invocation -> {
                        UserIdentity targetIdentity = authMgr
                                .getBestMatchedUserIdentity(JWT_USER, "127.0.0.1").getKey();
                        authMgr.alterUser(targetIdentity, createAuthenticationInfo(
                                targetIdentity, AuthPlugin.Server.AUTHENTICATION_OAUTH2.toString(),
                                MysqlPassword.EMPTY_PASSWORD, null), null);
                        return installAuthenticatedTarget(context, JWT_USER, targetPlugin, TARGET_AUTH_TOKEN);
                    });
            authorizer.when(() -> Authorizer.isRangerManagedContext(context)).thenReturn(false);

            Assertions.assertFalse(MysqlProto.changeUser(context, changeUserPacket));
        }

        previousState.assertRestored(context);
        Assertions.assertEquals(ErrorCode.ERR_AUTHENTICATION_FAIL, context.getState().getErrorCode());
    }

    @Test
    public void testChangeUserRejectsConcurrentTargetCredentialChange() throws Exception {
        AuthenticationStateSnapshot previousState = setDistinctAuthenticationState();
        String targetPlugin = AuthPlugin.Client.MYSQL_NATIVE_PASSWORD.toString();
        ByteBuffer changeUserPacket = createChangeUserPacket("user1", "password1", null);

        try (MockedStatic<AuthenticationHandler> authentication = Mockito.mockStatic(AuthenticationHandler.class);
                MockedStatic<Authorizer> authorizer = Mockito.mockStatic(Authorizer.class)) {
            authentication.when(() -> AuthenticationHandler.authenticate(
                            any(ConnectContext.class), any(String.class), any(String.class), any(byte[].class)))
                    .thenAnswer(invocation -> {
                        UserIdentity targetIdentity = authMgr
                                .getBestMatchedUserIdentity("user1", "127.0.0.1").getKey();
                        authMgr.alterUser(targetIdentity, createAuthenticationInfo(
                                targetIdentity, AuthPlugin.Server.MYSQL_NATIVE_PASSWORD.toString(),
                                MysqlPassword.makeScrambledPassword("rotated-password"), null), null);
                        return installAuthenticatedTarget(context, "user1", targetPlugin, TARGET_AUTH_TOKEN);
                    });
            authorizer.when(() -> Authorizer.isRangerManagedContext(context)).thenReturn(false);

            Assertions.assertFalse(MysqlProto.changeUser(context, changeUserPacket));
        }

        previousState.assertRestored(context);
        Assertions.assertEquals(ErrorCode.ERR_AUTHENTICATION_FAIL, context.getState().getErrorCode());
    }

    /**
     * Test change user with non-existent user
     */
    @Test
    public void testChangeUserNonExistentUser() throws IOException {
        // Create change user packet for non-existent user
        ByteBuffer changeUserPacket = createChangeUserPacket("nonexistent", "password", "new_db");
        
        // Save original user info for verification
        String originalUser = context.getQualifiedUser();
        String originalDb = context.getDatabase();
        UserIdentity originalUserIdentity = context.getCurrentUserIdentity();
        
        // Execute change user
        boolean result = MysqlProto.changeUser(context, changeUserPacket);
        
        // Verify failure and rollback
        Assertions.assertFalse(result, "Change user should fail for non-existent user");
        Assertions.assertEquals(originalUser, context.getQualifiedUser());
        Assertions.assertEquals(originalDb, context.getDatabase());
        Assertions.assertEquals(originalUserIdentity, context.getCurrentUserIdentity());
    }

    /**
     * Test change user with database switching failure
     */
    @Test
    public void testChangeUserDatabaseSwitchFailure() throws IOException {
        // Create change user packet with non-existent database
        ByteBuffer changeUserPacket = createChangeUserPacket("user1", "password1", "nonexistent_db");
        
        // Mock ConnectScheduler to return success
        new MockUp<ConnectScheduler>() {
            @Mock
            public com.starrocks.common.Pair<Boolean, String> onUserChanged(
                    ConnectContext context, String previousUser, String newUser) {
                return new com.starrocks.common.Pair<>(true, "");
            }
        };
        
        // Mock ExecuteEnv
        new MockUp<ExecuteEnv>() {
            @Mock
            public ConnectScheduler getScheduler() {
                return new ConnectScheduler(1000);
            }
        };
        
        AuthenticationStateSnapshot previousState = setDistinctAuthenticationState();

        // Save original user info for verification
        String originalUser = context.getQualifiedUser();
        String originalDb = context.getDatabase();
        UserIdentity originalUserIdentity = context.getCurrentUserIdentity();
        
        // Execute change user
        boolean result = MysqlProto.changeUser(context, changeUserPacket);
        
        // Verify failure and rollback
        Assertions.assertFalse(result, "Change user should fail when database switch fails");
        Assertions.assertEquals(originalUser, context.getQualifiedUser());
        Assertions.assertEquals(originalDb, context.getDatabase());
        Assertions.assertEquals(originalUserIdentity, context.getCurrentUserIdentity());
        previousState.assertRestored(context);
    }

    /**
     * Test change user with ConnectScheduler failure
     */
    @Test
    public void testChangeUserSchedulerFailure() throws IOException {
        // Create change user packet without database to avoid database switch failure
        ByteBuffer changeUserPacket = createChangeUserPacket("user1", "password1", null);
        
        // Mock ConnectScheduler to return failure
        new MockUp<ConnectScheduler>() {
            @Mock
            public com.starrocks.common.Pair<Boolean, String> onUserChanged(
                    ConnectContext context, String previousUser, String newUser) {
                return new com.starrocks.common.Pair<>(false, "Too many connections");
            }
        };
        
        // Mock ExecuteEnv
        new MockUp<ExecuteEnv>() {
            @Mock
            public ConnectScheduler getScheduler() {
                return new ConnectScheduler(1000);
            }
        };
        
        AuthenticationStateSnapshot previousState = setDistinctAuthenticationState();

        // Save original user info for verification
        String originalUser = context.getQualifiedUser();
        String originalDb = context.getDatabase();
        UserIdentity originalUserIdentity = context.getCurrentUserIdentity();
        
        // Execute change user
        boolean result = MysqlProto.changeUser(context, changeUserPacket);
        
        // Verify failure and rollback
        Assertions.assertFalse(result, "Change user should fail when scheduler rejects");
        Assertions.assertEquals(originalUser, context.getQualifiedUser());
        Assertions.assertEquals(originalDb, context.getDatabase());
        Assertions.assertEquals(originalUserIdentity, context.getCurrentUserIdentity());
        previousState.assertRestored(context);
        Assertions.assertEquals(ErrorCode.ERR_TOO_MANY_USER_CONNECTIONS, context.getState().getErrorCode());
    }

    /**
     * Test change user without database specification
     */
    @Test
    public void testChangeUserWithoutDatabase() throws IOException {
        // Create change user packet without database
        ByteBuffer changeUserPacket = createChangeUserPacket("user1", "password1", null);
        
        // Mock ConnectScheduler to return success
        new MockUp<ConnectScheduler>() {
            @Mock
            public com.starrocks.common.Pair<Boolean, String> onUserChanged(
                    ConnectContext context, String previousUser, String newUser) {
                return new com.starrocks.common.Pair<>(true, "");
            }
        };
        
        // Mock ExecuteEnv
        new MockUp<ExecuteEnv>() {
            @Mock
            public ConnectScheduler getScheduler() {
                return new ConnectScheduler(1000);
            }
        };
        
        // Execute change user
        boolean result = MysqlProto.changeUser(context, changeUserPacket);
        
        // Verify success - database should remain unchanged
        Assertions.assertTrue(result, "Change user should succeed without database change");
        Assertions.assertEquals("user1", context.getQualifiedUser());
        Assertions.assertEquals("test_db", context.getDatabase()); // Should remain original
    }

    /**
     * Test change user with database recovery on ConnectScheduler failure
     * This test verifies that when ConnectScheduler.onUserChanged() fails,
     * the database is properly recovered to its original state.
     */
    @Test
    public void testChangeUserDatabaseRecoveryOnSchedulerFailure() throws IOException {
        // Set up mock database environment similar to UseDbTest
        GlobalStateMgr globalStateMgr = GlobalStateMgr.getCurrentState();
        MockedLocalMetaStore localMetastore = new MockedLocalMetaStore(globalStateMgr, globalStateMgr.getRecycleBin(), null);
        localMetastore.init();
        globalStateMgr.setLocalMetastore(localMetastore);

        RBACMockedMetadataMgr metadataMgr =
                new RBACMockedMetadataMgr(localMetastore, globalStateMgr.getConnectorMgr());
        globalStateMgr.setMetadataMgr(metadataMgr);
        
        // Set up user identity with ROOT privileges
        context.setCurrentUserIdentity(UserIdentity.ROOT);
        context.setCurrentRoleIds(UserIdentity.ROOT);
        
        // Set up initial database state
        String originalDb = "db";
        String newDb = "db1";
        context.setDatabase(originalDb);
        
        // Create change user packet with database change
        ByteBuffer changeUserPacket = createChangeUserPacket("user1", "password1", newDb);
        
        // Mock Authorizer to allow database access
        new MockUp<Authorizer>() {
            @Mock
            public static void checkAnyActionOnOrInDb(ConnectContext context, String catalogName, String dbName) 
                    throws AccessDeniedException {
                // Allow access to all databases for testing
            }
        };
        
        // Mock ConnectScheduler to return failure (simulating user limit reached)
        new MockUp<ConnectScheduler>() {
            @Mock
            public com.starrocks.common.Pair<Boolean, String> onUserChanged(
                    ConnectContext context, String previousUser, String newUser) {
                return new com.starrocks.common.Pair<>(false, "Too many connections");
            }
        };
        
        // Mock ExecuteEnv
        new MockUp<ExecuteEnv>() {
            @Mock
            public ConnectScheduler getScheduler() {
                return new ConnectScheduler(1000);
            }
        };
        
        // Save original user info for verification
        String originalUser = context.getQualifiedUser();
        UserIdentity originalUserIdentity = context.getCurrentUserIdentity();
        
        // Execute change user
        boolean result = MysqlProto.changeUser(context, changeUserPacket);
        
        // Verify failure and database recovery
        Assertions.assertFalse(result, "Change user should fail when scheduler rejects");
        Assertions.assertEquals(originalUser, context.getQualifiedUser(), "User should be reverted");
        Assertions.assertEquals(originalUserIdentity, context.getCurrentUserIdentity(), "User identity should be reverted");
        Assertions.assertEquals(originalDb, context.getDatabase(), "Database should be recovered to original");
        Assertions.assertEquals(ErrorCode.ERR_TOO_MANY_USER_CONNECTIONS, context.getState().getErrorCode());
    }

    /**
     * Test change user with database recovery on database change failure
     * This test verifies that when database change fails, the user identity
     * is properly reverted to its original state.
     */
    @Test
    public void testChangeUserUserRecoveryOnDatabaseChangeFailure() throws IOException {
        // Create change user packet with non-existent database
        ByteBuffer changeUserPacket = createChangeUserPacket("user1", "password1", "nonexistent_db");
        
        // Mock ConnectScheduler to return success (we want to test database failure, not scheduler failure)
        new MockUp<ConnectScheduler>() {
            @Mock
            public com.starrocks.common.Pair<Boolean, String> onUserChanged(
                    ConnectContext context, String previousUser, String newUser) {
                return new com.starrocks.common.Pair<>(true, "");
            }
        };
        
        // Mock ExecuteEnv
        new MockUp<ExecuteEnv>() {
            @Mock
            public ConnectScheduler getScheduler() {
                return new ConnectScheduler(1000);
            }
        };
        
        // Save original user info for verification
        String originalUser = context.getQualifiedUser();
        String originalDb = context.getDatabase();
        UserIdentity originalUserIdentity = context.getCurrentUserIdentity();
        
        // Execute change user
        boolean result = MysqlProto.changeUser(context, changeUserPacket);
        
        // Verify failure and user recovery
        Assertions.assertFalse(result, "Change user should fail when database change fails");
        Assertions.assertEquals(originalUser, context.getQualifiedUser(), "User should be reverted");
        Assertions.assertEquals(originalUserIdentity, context.getCurrentUserIdentity(), "User identity should be reverted");
        Assertions.assertEquals(originalDb, context.getDatabase(), "Database should remain original");
    }

    /**
     * Helper method to create a change user packet
     */
    private ByteBuffer createChangeUserPacket(String username, String password, String database) {
        byte[] authResponse = password.isEmpty()
                ? MysqlPassword.EMPTY_PASSWORD : password.getBytes(StandardCharsets.UTF_8);
        return createChangeUserPacket(
                username, authResponse, database, AuthPlugin.Client.MYSQL_NATIVE_PASSWORD.toString());
    }

    private ByteBuffer createChangeUserPacket(
            String username, byte[] authResponse, String database, String pluginName) {
        MysqlSerializer serializer = MysqlSerializer.newInstance();
        
        // Command code for COM_CHANGE_USER
        serializer.writeInt1(MysqlCommand.COM_CHANGE_USER.getCommandCode());
        
        // Username
        serializer.writeNulTerminateString(username);
        
        serializer.writeInt1(authResponse.length);
        serializer.writeBytes(authResponse);
        
        // Database name (null-terminated)
        if (database != null) {
            serializer.writeNulTerminateString(database);
        } else {
            serializer.writeInt1(0); // Empty string
        }
        
        // Character set
        serializer.writeInt2(33); // UTF8
        
        if (pluginName != null) {
            serializer.writeNulTerminateString(pluginName);
        }
        
        return serializer.toByteBuffer();
    }

    private static MysqlSerializer createChangeUserPacketPrefix() {
        MysqlSerializer serializer = MysqlSerializer.newInstance();
        serializer.writeInt1(MysqlCommand.COM_CHANGE_USER.getCommandCode());
        serializer.writeNulTerminateString("user1");
        serializer.writeInt1(0);
        return serializer;
    }

    private static MysqlSerializer createChangeUserPacketThroughCharacterSet() {
        MysqlSerializer serializer = createChangeUserPacketPrefix();
        serializer.writeNulTerminateString("");
        serializer.writeInt2(33);
        return serializer;
    }

    private static MysqlSerializer createChangeUserPacketThroughPlugin() {
        MysqlSerializer serializer = createChangeUserPacketThroughCharacterSet();
        serializer.writeNulTerminateString(AuthPlugin.Client.MYSQL_NATIVE_PASSWORD.toString());
        return serializer;
    }

    private static void assertMalformedChangeUserPacket(MysqlSerializer serializer, String field) {
        MysqlChangeUserPacket packet = new MysqlChangeUserPacket(MysqlCapability.DEFAULT_CAPABILITY);
        Assertions.assertFalse(packet.readFrom(serializer.toByteBuffer()), field);
    }

    private AuthenticationStateSnapshot setDistinctAuthenticationState() {
        context.setCurrentRoleIds(new HashSet<>(Set.of(101L, 102L)));
        context.setGroups(new HashSet<>(Set.of("original-group")));
        context.setSecurityIntegration("original-security-integration");
        context.setDistinguishedName("original-distinguished-name");
        context.setAuthToken(ORIGINAL_AUTH_TOKEN);
        context.setOAuth2Context(ORIGINAL_OAUTH2_CONTEXT);
        context.setAuthPlugin(ORIGINAL_AUTH_PLUGIN);
        return AuthenticationStateSnapshot.capture(context);
    }

    private static void mutateAuthenticationState(ConnectContext context) {
        mutateAuthenticationState(context, "changed-user");
    }

    private static void mutateAuthenticationState(ConnectContext context, String user) {
        context.setCurrentUserIdentity(new UserIdentity(user, "changed-host"));
        context.setQualifiedUser(user);
        context.setCurrentRoleIds(new HashSet<>(Set.of(999L)));
        context.setGroups(new HashSet<>(Set.of("changed-group")));
        context.setSecurityIntegration("changed-security-integration");
        context.setDistinguishedName("changed-distinguished-name");
        context.setAuthToken(TARGET_AUTH_TOKEN);
        context.setOAuth2Context(TARGET_OAUTH2_CONTEXT);
        context.setAuthPlugin("changed-auth-plugin");
    }

    private UserIdentity installAuthenticatedTarget(
            ConnectContext targetContext, String user, String clientPlugin, String authToken) {
        UserIdentity matchedIdentity = authMgr.getBestMatchedUserIdentity(user, "127.0.0.1").getKey();
        targetContext.setCurrentUserIdentity(matchedIdentity);
        targetContext.setQualifiedUser(user);
        targetContext.setCurrentRoleIds(new HashSet<>(Set.of(999L)));
        targetContext.setGroups(new HashSet<>(Set.of("target-group")));
        targetContext.setSecurityIntegration("native");
        targetContext.setDistinguishedName("target-distinguished-name");
        targetContext.setAuthToken(authToken);
        targetContext.setOAuth2Context(null);
        targetContext.setAuthPlugin(clientPlugin);
        return matchedIdentity;
    }

    private static UserAuthenticationInfo createAuthenticationInfo(
            UserIdentity userIdentity, String serverPlugin, byte[] password, String authString)
            throws AuthenticationException {
        UserAuthenticationInfo authenticationInfo = new UserAuthenticationInfo();
        authenticationInfo.setAuthPlugin(serverPlugin);
        authenticationInfo.setPassword(password);
        authenticationInfo.setAuthString(authString);
        authenticationInfo.setOrigUserHost(userIdentity.getUser(), userIdentity.getHost());
        return authenticationInfo;
    }

    private static OAuth2Context createOAuth2Context(String prefix) {
        return new OAuth2Context(
                prefix + "-auth-server-url", prefix + "-token-server-url", prefix + "-redirect-url",
                prefix + "-client-id", prefix + "-client-secret", prefix + "-jwks-url", prefix + "-principal-field",
                new String[] {prefix + "-issuer"}, new String[] {prefix + "-audience"}, 30L);
    }

    private record AuthenticationStateSnapshot(UserIdentity currentUserIdentity, String qualifiedUser,
                                               Set<Long> currentRoleIds, Set<String> groups,
                                               String securityIntegration, String distinguishedName,
                                               String authToken, OAuth2Context oAuth2Context, String authPlugin) {
        private static AuthenticationStateSnapshot capture(ConnectContext context) {
            return new AuthenticationStateSnapshot(
                    context.getCurrentUserIdentity(), context.getQualifiedUser(),
                    copySet(context.getCurrentRoleIds()), copySet(context.getGroups()),
                    context.getSecurityIntegration(), context.getDistinguishedName(),
                    context.getAuthToken(), context.getOAuth2Context(), context.getAuthPlugin());
        }

        private void assertRestored(ConnectContext context) {
            Assertions.assertEquals(currentUserIdentity, context.getCurrentUserIdentity());
            Assertions.assertEquals(qualifiedUser, context.getQualifiedUser());
            Assertions.assertEquals(currentRoleIds, context.getCurrentRoleIds());
            Assertions.assertEquals(groups, context.getGroups());
            Assertions.assertEquals(securityIntegration, context.getSecurityIntegration());
            Assertions.assertEquals(distinguishedName, context.getDistinguishedName());
            Assertions.assertEquals(authToken, context.getAuthToken());
            Assertions.assertSame(oAuth2Context, context.getOAuth2Context());
            Assertions.assertEquals(authPlugin, context.getAuthPlugin());
        }

        private static <T> Set<T> copySet(Set<T> values) {
            return values == null ? null : new HashSet<>(values);
        }
    }
}

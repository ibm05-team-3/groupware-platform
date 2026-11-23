package com.goodlifecoder.groupware.security.mail;

import com.goodlifecoder.groupware.security.dao.PasswordResetTokenDAO;
import java.util.UUID;
import org.junit.jupiter.api.Test;

import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

class PasswordResetMailDispatcherTest {

    private static final UUID USER_ID = UUID.fromString("00000000-0000-0000-0000-000000000007");

    private final PasswordResetMailSender sender = mock(PasswordResetMailSender.class);
    private final PasswordResetTokenDAO tokens = mock(PasswordResetTokenDAO.class);
    private final PasswordResetMailDispatcher dispatcher = new PasswordResetMailDispatcher(sender, tokens);

    @Test
    void sendFailureRevokesTheToken() {
        doThrow(new IllegalStateException("smtp"))
                .when(sender)
                .send("resident-a@test.com", "http://localhost:5173/password-reset?token=raw-token");

        dispatcher.send(USER_ID, "resident-a@test.com", "http://localhost:5173/password-reset?token=raw-token");

        verify(tokens).revoke(USER_ID);
    }

    @Test
    void successfulSendKeepsTheToken() {
        dispatcher.send(USER_ID, "resident-a@test.com", "http://localhost:5173/password-reset?token=raw-token");

        verify(sender).send("resident-a@test.com", "http://localhost:5173/password-reset?token=raw-token");
        verifyNoInteractions(tokens);
    }
}

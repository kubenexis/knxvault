package dev.knxvault.client;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.IOException;

class ClientTest {
    @Test
    void healthRejectsClosedPort() {
        Client client = new Client("http://127.0.0.1:1", "");
        Assertions.assertThrows(IOException.class, client::health);
    }
}
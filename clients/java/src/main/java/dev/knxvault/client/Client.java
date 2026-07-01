package dev.knxvault.client;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import okhttp3.*;

import java.io.IOException;
import java.util.Map;

public final class Client {
    private final String baseUrl;
    private final String token;
    private final OkHttpClient http = new OkHttpClient();
    private final Gson gson = new Gson();

    public Client(String baseUrl, String token) {
        String envUrl = System.getenv("KNXVAULT_ADDR");
        String envToken = System.getenv("KNXVAULT_TOKEN");
        this.baseUrl = (baseUrl != null ? baseUrl : envUrl != null ? envUrl : "http://localhost:8200").replaceAll("/$", "");
        this.token = token != null ? token : envToken != null ? envToken : "";
    }

    public JsonObject health() throws IOException {
        return request("GET", "/health", null, false);
    }

    public void kvPut(String path, Map<String, Object> data) throws IOException {
        JsonObject body = new JsonObject();
        body.add("data", gson.toJsonTree(data));
        request("POST", "/secrets/kv/" + path.replaceFirst("^/", ""), body, true);
    }

    public JsonObject kvGet(String path) throws IOException {
        return request("GET", "/secrets/kv/" + path.replaceFirst("^/", ""), null, true);
    }

    private JsonObject request(String method, String path, JsonObject body, boolean auth) throws IOException {
        Request.Builder builder = new Request.Builder().url(baseUrl + path);
        if (auth && !token.isEmpty()) {
            builder.header("Authorization", "Bearer " + token);
        }
        if (body != null) {
            builder.method(method, RequestBody.create(gson.toJson(body), MediaType.parse("application/json")));
        } else {
            builder.method(method, null);
        }
        try (Response response = http.newCall(builder.build()).execute()) {
            if (!response.isSuccessful()) {
                throw new IOException("request failed: " + response.code());
            }
            ResponseBody responseBody = response.body();
            if (responseBody == null || responseBody.contentLength() == 0) {
                return new JsonObject();
            }
            return gson.fromJson(responseBody.string(), JsonObject.class);
        }
    }
}
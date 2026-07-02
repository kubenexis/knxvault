/** W40-06: Java client smoke example. */
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

public class HealthSmoke {
  public static void main(String[] args) throws Exception {
    String addr = System.getenv().getOrDefault("KNXVAULT_ADDR", "http://127.0.0.1:8200");
    HttpClient client = HttpClient.newHttpClient();
    HttpRequest req = HttpRequest.newBuilder(URI.create(addr + "/health")).GET().build();
    HttpResponse<String> res = client.send(req, HttpResponse.BodyHandlers.ofString());
    System.out.println(res.body());
  }
}
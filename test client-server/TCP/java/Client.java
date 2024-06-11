import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Random;

public class Client {
    private static final String HOST_ADDR = "127.0.0.1";
    private static final int HOST_PORT = 8082;
    private static final String SERVER_SNI_HOSTNAME = "test.com";

    public static void main(String[] args) {
        try {
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, new TrustManager[]{new TrustAllX509TrustManager()}, new SecureRandom());
            SSLSocketFactory factory = context.getSocketFactory();

            Socket socket = factory.createSocket(HOST_ADDR, HOST_PORT);
            System.out.println("SSL established.");

            long clientPid = ProcessHandle.current().pid();
            System.out.println("Client PID: " + clientPid);

            OutputStream out = socket.getOutputStream();
            InputStream in = socket.getInputStream();

            int count = 0;
            Random random = new Random();
            byte[] buffer = new byte[1024];
            while (true) {
                Thread.sleep(1000);
                int secret = random.nextInt(1024 * 1024 * 1024);
                String message = "Client random number " + count + " is " + secret + "\n";
                out.write(message.getBytes());
                out.flush();

                int bytesRead = in.read(buffer);
                if (bytesRead > 0) {
                    String response = new String(buffer, 0, bytesRead);
                    System.out.println(response);
                }
                count++;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static class TrustAllX509TrustManager implements X509TrustManager {
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }

        public void checkClientTrusted(X509Certificate[] certs, String authType) {
        }

        public void checkServerTrusted(X509Certificate[] certs, String authType) {
        }
    }
}

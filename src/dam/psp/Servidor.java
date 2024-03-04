package dam.psp;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class Servidor {

	private final ExecutorService POOL = Executors.newCachedThreadPool();

	Servidor(int port) throws IOException {
		ServerSocket serverSocket = new ServerSocket(port);

		log(serverSocket.getInetAddress(), "info", "listening on " + port);

		for (int i = 0; i < 50; i++) {
			POOL.submit(() -> {
				try {
					listen(serverSocket);
				} catch (IOException e) {
					e.printStackTrace();
				}
			});
		}

	}

	private void listen(ServerSocket ss) throws IOException {
		while (true) {
			try (Socket client = ss.accept();
					DataInputStream in = new DataInputStream(client.getInputStream());
					DataOutputStream out = new DataOutputStream(client.getOutputStream())) {
				client.setSoTimeout(3000);
				try {
					String request = in.readUTF();

					switch (request) {
					case "hash":
						hashRequest(client, in, out);
						break;
					case "cert":
						certRequest(client, in, out);
						break;
					case "cifrar":
						cifrarRequest(client, in, out);
						break;
					default:
						out.writeUTF("ERROR:'" + request + "' no se reconoce como una petición válida");
					}
					log(client.getInetAddress(), "request", request);

				} catch (SocketTimeoutException e) {
					log(client.getInetAddress(), "error", "timeout");
					out.writeUTF("ERROR:Read timed out");
				} catch (EOFException e) {
					log(client.getInetAddress(), "error", "EOF");
					out.writeUTF("ERROR:Se esperaba una petición");
				}

			}
		}
	}

	/**
	 * Hash Request
	 * 
	 * @param client
	 * @param in
	 * @param out
	 * @throws IOException
	 */
	private void hashRequest(Socket client, DataInputStream in, DataOutputStream out) throws IOException {
		String algorithm;
		byte[] message;
		try {
			algorithm = in.readUTF();
		} catch (SocketTimeoutException e) {
			log(client.getInetAddress(), "error", "timeout:algorithm");
			out.writeUTF("ERROR:Read timed out");
			return;
		} catch (EOFException e) {
			log(client.getInetAddress(), "error", "timeout:algorithm");
			out.writeUTF("ERROR:Se esperaba un algoritmo");
			return;
		}

		try {
			message = in.readAllBytes();
		} catch (SocketTimeoutException e) {
			log(client.getInetAddress(), "error", "timeout:message");
			out.writeUTF("ERROR:Read timed out");
			return;
		} catch (EOFException e) {
			log(client.getInetAddress(), "error", "timeout:message");
			out.writeUTF("ERROR:Se esperaban datos");
			return;
		}

		MessageDigest md;
		try {
			md = MessageDigest.getInstance(algorithm);
		} catch (NoSuchAlgorithmException e) {
			log(client.getInetAddress(), "error", "notfound:algorithm");
			out.writeUTF("ERROR:Algoritmo no encontrado");
			return;
		}
		String hashB64 = Base64.getEncoder().encodeToString(md.digest(message));
		out.writeUTF("OK:" + hashB64);
	}

	/**
	 * Certificate request
	 * 
	 * @param client
	 * @param in
	 * @param out
	 * @throws IOException
	 */
	private void certRequest(Socket client, DataInputStream in, DataOutputStream out) throws IOException {
		String alias;
		String certHash;

		try {
			alias = in.readUTF();
		} catch (SocketTimeoutException e) {
			log(client.getInetAddress(), "error", "timeout:algorithm");
			out.writeUTF("ERROR:Read timed out");
			return;
		} catch (EOFException e) {
			log(client.getInetAddress(), "error", "timeout:algorithm");
			out.writeUTF("ERROR:Se esperaba un alias");
			return;
		}

		try {
			certHash = in.readUTF();
		} catch (SocketTimeoutException e) {
			log(client.getInetAddress(), "error", "timeout:algorithm");
			out.writeUTF("ERROR:Read timed out");
			return;
		} catch (EOFException e) {
			log(client.getInetAddress(), "error", "timeout:algorithm");
			out.writeUTF("ERROR:Se esperaba un certificado");
			return;
		}

		KeyStore ks;
		try {
			ks = KeyStore.getInstance("PKCS12");
		} catch (KeyStoreException e) {
			e.printStackTrace();
			return;
		}
		try {
			ks.load(new FileInputStream("res/keystore.p12"), "practicas".toCharArray());
		} catch (NoSuchAlgorithmException | CertificateException | IOException e) {
			e.printStackTrace();
		}

		Certificate cert;
		try {
			cert = ks.getCertificate(alias);
		} catch (KeyStoreException e) {
			e.printStackTrace();
			return;
		}

		String b64;
		try {
			b64 = Base64.getEncoder().encodeToString(cert.getEncoded());
		} catch (CertificateEncodingException e) {
			e.printStackTrace();
			return;
		}
		MessageDigest md;
		try {
			md = MessageDigest.getInstance("SHA-256");
		} catch (NoSuchAlgorithmException ignored) {
			return;
		}
		md.update(b64.getBytes());
		String b64HashB64 = Base64.getEncoder().encodeToString(md.digest());
		out.writeUTF("OK:" + b64HashB64);

	}

	/**
	 * Cifrar Request
	 * 
	 * @param client
	 * @param in
	 * @param out
	 * @throws IOException
	 */
	private void cifrarRequest(Socket client, DataInputStream in, DataOutputStream out) throws IOException {
		String alias;
		String certHash;
		byte[] data;

		// TODO: "ERROR:'aliasnoválido' no es un certificado"
		try {
			alias = in.readUTF();
		} catch (SocketTimeoutException e) {
			log(client.getInetAddress(), "error", "timeout:algorithm");
			out.writeUTF("ERROR:Read timed out");
			return;
		} catch (EOFException e) {
			log(client.getInetAddress(), "error", "timeout:algorithm");
			out.writeUTF("ERROR:Se esperaba un alias");
			return;
		}

		// TODO: "ERROR:'alumno' no contiene una clave RSA"
		try {
			certHash = in.readUTF();
		} catch (SocketTimeoutException e) {
			log(client.getInetAddress(), "error", "timeout:cert");
			out.writeUTF("ERROR:Read timed out");
			return;
		} catch (EOFException e) {
			log(client.getInetAddress(), "error", "timeout:cert");
			out.writeUTF("ERROR:Se esperaba un certificado");
			return;
		}

		try {
			data = in.readAllBytes();
		} catch (SocketTimeoutException e) {
			log(client.getInetAddress(), "error", "timeout:message");
			out.writeUTF("ERROR:Read timed out");
			return;
		} catch (EOFException e) {
			log(client.getInetAddress(), "error", "timeout:message");
			out.writeUTF("ERROR:Se esperaban datos");
			return;
		}
	}

	private String byteArrayToUTF(byte[] bytes) {
		StringBuilder sb = new StringBuilder();
		for (byte b : bytes)
			sb.append((char) b);
		return sb.toString();

	}

	private void log(InetAddress address, String type, String message) {
		System.out.printf("(%s):%s:%s%n", address, type, message);
	}

	public static void main(String[] args) throws IOException {
		Servidor server = new Servidor(9000);
	}

}

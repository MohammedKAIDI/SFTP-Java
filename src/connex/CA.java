package connex;

import java.io.ByteArrayInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CRL;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.GregorianCalendar;
import java.util.Iterator;
import java.util.Random;
import java.util.Set;

import javax.net.ssl.KeyManagerFactory;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ocsp.OCSPRequest;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V1CertificateGenerator;

public class CA {

	private final X500Principal IssuerDN = new X500Principal("CN= CERT_Auth");
	private ServerSocketChannel serverSocketChannel;
	private ByteBuffer byteBuffer;
	private SocketChannel socketChannel;
	private Selector selector;
	private KeyPair pair;
	private X509Certificate Ca_certificate;
	private KeyStore keyStore;
	protected static String home = System.getProperty("user.home");
	private String path = home + "/Application/CA/";
	private boolean keystore_created = false ; 
	private OCSPRequest ocspreq;
	private File theDir ; 
	
	
	public void make_Dir(String path) {
		theDir = new File(path);
		if (!theDir.exists()) {
			boolean result = false;

			try {
				theDir.mkdir();
				result = true;
			} catch (SecurityException se) {
			}
			if (result) {
			//	System.out.println("DIR created");
			}
		}
	}
	
	
	public CA(int port) throws Exception {
		
		
		make_Dir(home + "/Application");
		make_Dir(home +"/Application/CA");
		
		Security.addProvider(new BouncyCastleProvider());
		
		serverSocketChannel = ServerSocketChannel.open();
		
		serverSocketChannel.configureBlocking(false);
		
		serverSocketChannel.bind(new InetSocketAddress(port));
		
		selector = Selector.open();
		
		serverSocketChannel.register(selector, SelectionKey.OP_ACCEPT);
		
		byteBuffer = ByteBuffer.allocate(2000000);
		
		KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA", "BC");
		
		gen.initialize(2048);
		
		KeyPair pair = gen.generateKeyPair();
		
		this.pair = pair;
		
		Ca_certificate = CA_certificate();
		
		keyStore = KeyStore.getInstance("UBER");
		
		keyStore.load(null, null);
		
		save_In_Keystore(Ca_certificate, "ca_certificate");
		
		display_Keystore();
		//System.out.println("CA "+ Ca_certificate);
	}
	
	
	
	public static void main(String[] args) throws Exception {
		
		CA ca = new CA(1963);
		//ca.display_Keystore();
		ca.get_And_Serve();
	}
	

	final char[] JKS_PASSWORD = "persona".toCharArray();
	final char[] KEY_PASSWORD = "pass".toCharArray();

	
	public void save_In_Keystore(X509Certificate certificate, String alias)
				throws Exception {

		//System.out.println(" alias = "+ alias);
		
		File f = new File(path + "ca_keystore");
		//if(keystore_created){
		
		if(f.exists())
		keyStore.load(new FileInputStream(path + "ca_keystore"), KEY_PASSWORD);
		
		//}
		
		final KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");

		kmf.init(keyStore, KEY_PASSWORD);

		keyStore.setCertificateEntry(alias, certificate);

		//System.out.println("Entry certif : " + keyStore.isCertificateEntry(alias));

		keyStore.store(new FileOutputStream(path + "ca_keystore"), KEY_PASSWORD);
		
		keystore_created = true; 
	
	}

	public void display_Keystore() throws Exception {

		//if(keystore_created){
				
		keyStore.load(new FileInputStream(home + "/Application/CA/ca_keystore"), KEY_PASSWORD);

		//System.out.println(keyStore.size());

		Enumeration<String> enu = keyStore.aliases();
		
		System.out.println("The Keystore of CA : \n");
		
		while (enu.hasMoreElements()) {
			
			System.out.println("Alias : " + enu.nextElement());
		//}
		
		}
	}
	
	
	
	
	public void verify_Certificate() throws Exception {

		if(keystore_created){
			
		Collection crls = null ; 
		Calendar calendar = null ;
		if (calendar == null)
			calendar = new GregorianCalendar();	
		
				
		keyStore.load(new FileInputStream(home + "/Application/CA/ca_keystore"), KEY_PASSWORD);

		//System.out.println(keyStore.size());

		Enumeration<String> enu = keyStore.aliases();
		
		//System.out.println("The Keystore of CA : \n");
		
		while (enu.hasMoreElements()) {
			
			String alias = enu.nextElement();
			
			//System.out.println("Alias : " + alias);
			
			X509Certificate certif = get_Certificate(alias);
			
			if(certif.hasUnsupportedCriticalExtension()){
				System.out.println(alias + " Has unsupported critical extension");
			}
			 try {
			        certif.checkValidity(calendar.getTime());
			    }
			    catch (Exception e) {
			        System.out.println(e.getMessage());
			    }
			 
			
			 if (crls != null) {
			        for (Iterator it = crls.iterator(); it.hasNext();) {
			            if (((CRL)it.next()).isRevoked(certif))
			                System.out.println("Certificate revoked");
			        }			
		}
		
		}
		}
		
		}
	
	
	
	

	public X509Certificate get_Certificate(String alias) throws KeyStoreException{
		
		return (X509Certificate) keyStore.getCertificate(alias);
	}
	
	
	public byte[] Sign_a_Certificate(X509Certificate certificate) throws Exception {
		
		byte[] certif_byte = certificate.getEncoded();

		Signature sig = Signature.getInstance("SHA1withRSA");
		sig.initSign(pair.getPrivate());
		sig.update(certif_byte);
		byte[] signed = sig.sign();
		
		System.out.println("A certificate is signed ... ");
		
		return signed ;
	}

	public X509Certificate CA_certificate() throws Exception {
		
		X509V1CertificateGenerator certif = new X509V1CertificateGenerator();
		
		X500Principal x500p = new X500Principal("CN=Nighto");
		
		int duration = 0;
		
		Date startdate = new Date();
		
		certif.setSubjectDN(x500p);
		
		certif.setPublicKey(pair.getPublic());
		
		BigInteger m = new BigInteger("687");
		
		certif.setSerialNumber(nextRandomBigInteger(m));
		
		certif.setIssuerDN(IssuerDN);
		
		certif.setNotAfter(setDuration(duration, startdate));
		
		certif.setNotBefore(startdate);
		
		certif.setSignatureAlgorithm("SHA1withRSA");
		
		X509Certificate cert = certif.generate(pair.getPrivate());
		
		return cert;
	}
	
	/**
	 * 
	 * @param pkcs
	 * @param startdate
	 * @param duration
	 * @param pv
	 * @return certificat
	 * @throws Exception
	 *             Cette méthode a pour role la création d'un certificat , ceci
	 *             est fais en lisant les demandes CSR des diffts clients
	 */
	@SuppressWarnings("deprecation")
	
	public X509Certificate generateCertif(
			@SuppressWarnings({ "deprecation", "deprecation" }) 
			PKCS10CertificationRequest pkcs, Date startdate,
			int duration, PrivateKey pv) throws Exception {

		@SuppressWarnings("deprecation")
		X509V1CertificateGenerator certif = new X509V1CertificateGenerator();

		X500Name x500 = pkcs.getCertificationRequestInfo().getSubject();
		
		X500Principal x500p = new X500Principal(x500.getEncoded());

		certif.setSubjectDN(x500p);
		
		certif.setPublicKey(pkcs.getPublicKey());
		
		BigInteger m = new BigInteger("687");
		
		certif.setSerialNumber(nextRandomBigInteger(m));
		
		certif.setIssuerDN(IssuerDN);
		
		certif.setNotAfter(setDuration(duration, startdate));
		
		certif.setNotBefore(startdate);
		
		certif.setSignatureAlgorithm("SHA1withRSA");
		
		X509Certificate cert = certif.generate(pv);
		
		System.out.println("A certificate is generated for "+x500.toString());
		
		return cert;
	}

	/**
	 * 
	 * @param n
	 * @return Pour generer un nombre BigInteger aléatoire -> le serial number.
	 */
	public static BigInteger nextRandomBigInteger(BigInteger n) {
		Random rnd = new Random();
		int nlen = n.bitLength();
		BigInteger nm1 = n.subtract(BigInteger.ONE);
		BigInteger r, s;
		do {
			s = new BigInteger(nlen + 100, rnd);
			r = s.mod(n);
		} while (s.subtract(r).add(nm1).bitLength() >= nlen + 100);
		return s;
	}

	/**
	 * 
	 * @param duration
	 * @param startDate
	 * @return date
	 */
	public static Date setDuration(int duration, Date startDate) {
		Calendar c = new GregorianCalendar();
		c.setTime(startDate);
		c.add(Calendar.DATE, 90);
		Date d = c.getTime();
		return d;
	}

	/**
	 * 
	 * @param path
	 * @return pkcs
	 * @throws IOException
	 *             pour recuperer une demande CSR.
	 */
	@SuppressWarnings("deprecation")
	public static PKCS10CertificationRequest getPKCSfromPath(String path) throws IOException {
		FileInputStream in = new FileInputStream(path);
		byte[] b = new byte[in.available()];
		in.read(b);
		PKCS10CertificationRequest pkcs = new PKCS10CertificationRequest(b);
		return pkcs;
	}

	/**
	 * 
	 * @return KeyPair
	 * @throws Exception
	 *             Cette methode a pour role la creation d'une pair de clés en
	 *             utilisant l'algo RSA
	 */
	public KeyPair getPair() throws NoSuchAlgorithmException, NoSuchProviderException {
		KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA", "BC");
		gen.initialize(2048);
		KeyPair pair = gen.generateKeyPair();
		return pair;
	}

	public void send(X509Certificate TheCertif, Socket sk) throws Exception {
		Socket send = new Socket();
		String addr = sk.getInetAddress().toString();

		int port = sk.getPort();
		System.out.println("New client accepted : " + addr + " " + port);

		send.connect(new InetSocketAddress(addr, port));
		System.out.println("Connexion state : " + send.isConnected());
		DataOutputStream da = new DataOutputStream(send.getOutputStream());
		byte[] certiftoSend = TheCertif.getEncoded();
		da.writeInt(certiftoSend.length);
		da.write(certiftoSend);
	}

	public void get_And_Serve() throws Exception {
		while (true) {
			System.out.println("Waiting .... ");
			try {
				selector.select();
			} catch (IOException e) {
				e.printStackTrace();
			}
			Set<SelectionKey> selectionKeys = selector.selectedKeys();
			Iterator<SelectionKey> it = selectionKeys.iterator();
			while (it.hasNext()) {

				SelectionKey key = it.next();

				if (key.isAcceptable()) {
					SocketChannel sc = serverSocketChannel.accept();
					System.out.println("client : " + sc.getRemoteAddress());
					sc.configureBlocking(false);
					sc.register(selector, SelectionKey.OP_READ);
				}

				if (key.isReadable()) {
					SocketChannel sc = (SocketChannel) key.channel();
					byteBuffer.clear();
					int r = sc.read(byteBuffer);
					byteBuffer.flip();
					if (r == -1) {
						sc.finishConnect();
						sc.register(selector, SelectionKey.OP_CONNECT);
						key.cancel();
					} else {
						int ID = byteBuffer.getInt();
						//System.out.println("ID !!! " + ID);

						switch (ID) {

						case 1:	
							
							System.out.println("ID : 1 --> Certificate request ");
							
							String connexion_name = Conversion_SB.Buf_To_String(byteBuffer);
							
							PrivateKey privateKey = pair.getPrivate();
														
							String path = Conversion_SB.Buf_To_String(byteBuffer);
							
							//System.out.println("Path = " + path);
							@SuppressWarnings("deprecation")
							
							PKCS10CertificationRequest pkcs = getPKCSfromPath(path);
							
							Date today = new Date();
							
							X509Certificate TheCertif = generateCertif(pkcs, today, 90, privateKey);
							
							save_In_Keystore(TheCertif, "certif_"+ connexion_name);
							
							
							X509Certificate c = get_Certificate("certif_"+ connexion_name);
							//System.out.println("Cer "+ connexion_name +" "+ c);
							
							byte[] sig_certif = Sign_a_Certificate(TheCertif);
							
							//System.out.println("path : " + path);
							
							//System.out.println("CA : Signed certif : "+ new String(sig_certif,"UTF8"));
							
							byteBuffer.clear();
							
							// we send the certificate
							int length_certif = TheCertif.getEncoded().length;
							byteBuffer.putInt(length_certif);
							byteBuffer.put(TheCertif.getEncoded());
							
							// we send the signed form of the certificate
							
							byteBuffer.putInt(sig_certif.length);
							byteBuffer.put(sig_certif);
							
							byteBuffer.flip();
							
							while (byteBuffer.hasRemaining())
								sc.write(byteBuffer);
							
							byteBuffer.clear();
							
							display_Keystore();
							
							
							byteBuffer.clear();
							break;
							
						case 3:
							
							path = Conversion_SB.Buf_To_String(byteBuffer);
							
							byteBuffer.clear();
							
							byte[] ca_signed = Sign_a_Certificate(Ca_certificate);
							
							// we send the ca certificate 
							byteBuffer.putInt(Ca_certificate.getEncoded().length);
							
							//System.out.println("Int "+ Ca_certificate.getEncoded().length);
							
							byteBuffer.put(Ca_certificate.getEncoded());
							
							// we send the signed form of the certificate 
							
							byteBuffer.putInt(ca_signed.length);
							byteBuffer.put(ca_signed);
							
							byteBuffer.flip();
							
							while (byteBuffer.hasRemaining())
								sc.write(byteBuffer);
							
							byteBuffer.clear();
							
							break;
						
						case 2 :
							String cl_name = Conversion_SB.Buf_To_String(byteBuffer);
							int certif_len = byteBuffer.getInt();
							byte[] certif_byte = new byte[certif_len];
							byteBuffer.get(certif_byte);
							
							CertificateFactory cf = CertificateFactory.getInstance("X509");
							X509Certificate certificate = 
						   (X509Certificate) 
						   cf.generateCertificate(new ByteArrayInputStream(certif_byte));
							
							
							if(verify_equitability(certificate, cl_name))
							{
								byteBuffer.clear();
								
								byteBuffer.putInt(5);
								String s = "OK";
								Conversion_SB.String_To_Buf(byteBuffer, s);
								byteBuffer.flip();
								int n = 0 ;
								while(byteBuffer.hasRemaining())
									n =	sc.write(byteBuffer);
								
							}
							else {
								byteBuffer.clear();
								byteBuffer.putInt(401);
								byteBuffer.flip(); 
								System.out.println("Not matched  ");
								while(byteBuffer.hasRemaining()){
									sc.write(byteBuffer);
								}
								
							}
						
						byteBuffer.clear();
							
						default:
							break;
						}
					}
					byteBuffer.clear();

				}
				it.remove();
			}
		}
	}

	public boolean verify_equitability(X509Certificate certif , String cl_name) throws Exception{
		
		//System.out.println("Client name : "+ cl_name);
		X509Certificate recup_from_keystore = get_Certificate("certif_"+cl_name);
		
		//System.out.println("Recup : "+ recup_from_keystore);
		
//		System.out.println("Serial 2 "+ recup_from_keystore.getSerialNumber());

		return certif.equals(recup_from_keystore);
		
	}
	
	
	public SocketChannel getSocketChannel() {
		return socketChannel;
	}

	public void setSocketChannel(SocketChannel socketChannel) {
		this.socketChannel = socketChannel;
	}

}
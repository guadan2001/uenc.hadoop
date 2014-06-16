package uenc_cpabe;

import java.io.ByteArrayInputStream;
import java.security.MessageDigest;

import javax.print.DocFlavor.BYTE_ARRAY;

import bswabe.SerializeUtils;
import cpabe.Common;
import it.unisa.dia.gas.jpbc.CurveGenerator;
import it.unisa.dia.gas.jpbc.CurveParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.DefaultCurveParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;

public class UpdatableEncryption {

	public UpdatableEncryption()
	{

	}
	
	private Element g;
	private Element h;

//	private static String curveParams = "type a\n"
//			+ "q 87807107996633125224377819847540498158068831994142082"
//			+ "1102865339926647563088022295707862517942266222142315585"
//			+ "8769582317459277713367317481324925129998224791\n"
//			+ "h 12016012264891146079388821366740534204802954401251311"
//			+ "822919615131047207289359704531102844802183906537786776\n"
//			+ "r 730750818665451621361119245571504901405976559617\n"
//			+ "exp2 159\n" + "exp1 107\n" + "sign1 1\n" + "sign0 1\n";
	
	private static String curveParams = "type f\n"
			+ "q 205523667896953300194896352429254920972540065223\n"
			+ "r 205523667896953300194895899082072403858390252929\n"
			+ "b 40218105156867728698573668525883168222119515413\n"
			+ "beta 115334401956802802075595682801335644058796914268\n"
			+ "alpha0 191079354656274778837764015557338301375963168470\n"
			+ "alpha1 71445317903696340296199556072836940741717506375\n";

	public void uSetup(String ugpFile, String xFile) throws Exception
	{
		CurveParameters params = new DefaultCurveParameters()
		.load(new ByteArrayInputStream(curveParams.getBytes()));
		Pairing pairing = PairingFactory.getPairing(params);

		UencUgp ugp = new UencUgp();
		ugp.ugp = pairing.getGT().newElement();
		ugp.g = pairing.getG1().newRandomElement();
		ugp.h = pairing.getG2().newRandomElement();
		
		Element x = pairing.getZr().newRandomElement();
		
		ugp.ugp = pairing.pairing(ugp.g, ugp.h);
		ugp.ugp.powZn(x);
		
		byte[] ugpByte = Utils.serializeUgp(ugp);
		byte[] xByte = Utils.serializeX(x);
		Utils.spitFile(ugpFile, ugpByte);
		Utils.spitFile(xFile, xByte);		
	}

	public void uKeygen(String ugpFile, String xFile, String uskFile) throws Exception {
		
		byte[] ugpByte = Utils.suckFile(ugpFile);
		UencUgp ugp = Utils.unserializeUgp(ugpByte);
		byte[] xByte = Utils.suckFile(xFile);
		Element x = Utils.unserializeX(xByte);
		
		UencUsk usk = new UencUsk();
		Pairing pairing = Utils.getPairing();
		
		Element a = pairing.getZr().newElement();
		a.setToRandom();
		
		usk.g_pow_a = ugp.g.duplicate();
		usk.g_pow_a = usk.g_pow_a.powZn(a);
		usk.h_pow_x_divide_a = ugp.h.duplicate();
		usk.h_pow_x_divide_a = usk.h_pow_x_divide_a.powZn(x);
		a.invert();
		usk.h_pow_x_divide_a = usk.h_pow_x_divide_a.powZn(a);
		
		System.out.println("USK: " + usk.g_pow_a.toString() + " " + usk.h_pow_x_divide_a.toString());
		
		byte[] uskByte = Utils.serializeUsk(usk);
		Utils.spitFile(uskFile, uskByte);
	}

	public void uEncrypt(String ugpFile, String uskFile, String inputFile, String encrytedFile) throws Exception{
		byte[] ugpByte = Utils.suckFile(ugpFile);
		UencUgp ugp = Utils.unserializeUgp(ugpByte);
		byte[] uskByte = Utils.suckFile(uskFile);
		UencUsk usk = Utils.unserializeUsk(uskByte);
		Pairing pairing = Utils.getPairing();
		
		byte[] inputBuffer;
		byte[] c1Buffer;
		
		inputBuffer = Utils.suckFile(inputFile);
		Element c1 = ugp.ugp.duplicate();
		Element c2 = usk.g_pow_a.duplicate();
		
		Element s = pairing.getZr().newElement();
		s.setToRandom();
		
		c1.powZn(s);
		c2.powZn(s);
		
		System.out.println("c1 length: " + c1.toBytes().length + " bytes");
		System.err.println(c1.toString());
		
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		md.update(c1.toBytes());
		c1Buffer = AESCoder.encrypt(md.digest(), inputBuffer);
		Utils.writeEncryptedFile(encrytedFile, c1Buffer, c2.toBytes());
	}

	public void uDecrypt(String encrytedFile, String decryptFile, String uskFile) throws Exception{
		
		Pairing pairing = Utils.getPairing();
		
		byte[][] encrytedBuffer;
		byte[] decryptedBuffer;
		encrytedBuffer = Utils.readEncryptedFile(encrytedFile);
		
		Element c2 = pairing.getG1().newElement();
		c2.setFromBytes(encrytedBuffer[1]);
		Element h_pow_x_divide_a = pairing.getG2().newElement();
		
		byte[] uskBytes = Utils.suckFile(uskFile);
		UencUsk usk = Utils.unserializeUsk(uskBytes);
		
		h_pow_x_divide_a = usk.h_pow_x_divide_a.duplicate();
		
		Element xs = pairing.pairing(c2, h_pow_x_divide_a);
		
		System.out.println("xs length: " + xs.toBytes().length + " bytes");
		System.out.println(xs.toString());
		
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		md.update(xs.toBytes());
		
		decryptedBuffer = AESCoder.decrypt(md.digest(), encrytedBuffer[0]);
		Utils.spitFile(decryptFile, decryptedBuffer);
	}

	public void uKeyUpdate(String uskFile, String newUskFile, String rkFile) throws Exception{
		Pairing pairing = Utils.getPairing();
		byte[] uskByte = Utils.suckFile(uskFile);
		UencUsk usk = Utils.unserializeUsk(uskByte);
		
		Element rk = pairing.getZr().newRandomElement();
		
		UencUsk usk_new = new UencUsk();
		usk_new.g_pow_a = usk.g_pow_a.duplicate();
		usk_new.h_pow_x_divide_a = usk.h_pow_x_divide_a.duplicate();
		
		Element a1 = rk.duplicate();
		a1.invert();
		usk_new.g_pow_a.powZn(rk);
		usk_new.h_pow_x_divide_a.powZn(a1);
		
		byte[] newUskByte = Utils.serializeUsk(usk_new);
		byte[] rkByte = Utils.serializeRk(rk);
		Utils.spitFile(newUskFile, newUskByte);
		Utils.spitFile(rkFile, rkByte);
		
		System.out.println("USK_NEW: " + usk_new.g_pow_a.toString() + " " + usk_new.h_pow_x_divide_a.toString());
	}

	public void uEncUpdate(String rkFile, String encrytedFile, String updatedFile) throws Exception{
		Pairing pairing = Utils.getPairing();
		
		byte[][] encrytedBuffer;
		encrytedBuffer = Utils.readEncryptedFile(encrytedFile);
		byte[] rkByte = Utils.suckFile(rkFile);
		Element rk = Utils.unserializeRk(rkByte);
		
		Element c2 = pairing.getG1().newElement();
		c2.setFromBytes(encrytedBuffer[1]);
		System.out.println("c2 = " + c2.toString());
		c2.powZn(rk);
		
		System.err.println(c2.toString());
		
		Utils.writeEncryptedFile(updatedFile, encrytedBuffer[0], c2.toBytes());
	}
}
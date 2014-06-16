package uenc_cpabe;
import it.unisa.dia.gas.jpbc.CurveParameters;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.plaf.jpbc.pairing.DefaultCurveParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.util.ArrayList;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FSDataInputStream;
import org.apache.hadoop.fs.FSDataOutputStream;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;

public class Utils {
	
	private static String curveParams = "type f\n"
			+ "q 205523667896953300194896352429254920972540065223\n"
			+ "r 205523667896953300194895899082072403858390252929\n"
			+ "b 40218105156867728698573668525883168222119515413\n"
			+ "beta 115334401956802802075595682801335644058796914268\n"
			+ "alpha0 191079354656274778837764015557338301375963168470\n"
			+ "alpha1 71445317903696340296199556072836940741717506375\n";

	/* read byte[] from inputfile */
	public static byte[] suckFile(String inputfile) throws IOException {
		Configuration conf = new Configuration(); 
        conf.set("hadoop.job.ugi", "hadoop-user,hadoop-user"); 
        
        System.out.println(inputfile);
         
        FileSystem fs = FileSystem.get(URI.create(inputfile),conf); 
        FSDataInputStream in = null; 
        try{ 
            in = fs.open( new Path(inputfile) );
            int size = in.available();
            byte[] content = new byte[size];
            in.read(content);
            
            in.close();
            
            return content;
            
        }finally{ 
            in.close();
        } 
	}

	/* write byte[] into outputfile */
	public static void spitFile(String outputfile, byte[] b) throws IOException {
		Configuration conf = new Configuration(); 
        conf.set("hadoop.job.ugi", "hadoop-user,hadoop-user"); 
         
        FileSystem fs = FileSystem.get(URI.create(outputfile),conf);
        FSDataOutputStream out = null;
        try{ 
        	out = fs.create(new Path(outputfile));
        	out.write(b);
        	out.close();
            
        }finally{ 
            out.close();
        } 
	}


	public static void writeEncryptedFile(String encryptedFile,
			byte[] c1Buf, byte[] c2Buf) throws IOException {
		int i;
		Configuration conf = new Configuration(); 
        conf.set("hadoop.job.ugi", "hadoop-user,hadoop-user"); 
         
        FileSystem fs = FileSystem.get(URI.create(encryptedFile),conf);
        FSDataOutputStream os = null;
        
        os = fs.create(new Path(encryptedFile));

		/* write aes_buf */
		for (i = 3; i >= 0; i--)
			os.write(((c1Buf.length & (0xff << 8 * i)) >> 8 * i));
		os.write(c1Buf);

		/* write cph_buf */
		for (i = 3; i >= 0; i--)
			os.write(((c2Buf.length & (0xff << 8 * i)) >> 8 * i));
		os.write(c2Buf);

		os.close();

	}

	public static byte[][] readEncryptedFile(String encryptFile) throws IOException {
		int i, len;
		
		Configuration conf = new Configuration(); 
        conf.set("hadoop.job.ugi", "hadoop-user,hadoop-user"); 
         
        FileSystem fs = FileSystem.get(URI.create(encryptFile),conf); 
        FSDataInputStream is = null; 
        is = fs.open( new Path(encryptFile) );
		
		byte[][] res = new byte[2][];
		byte[] c1Buf, c2Buf;

		len = 0;
		for (i = 3; i >= 0; i--)
			len |= is.read() << (i * 8);
		c1Buf = new byte[len];

		is.read(c1Buf);

		len = 0;
		for (i = 3; i >= 0; i--)
			len |= is.read() << (i * 8);
		c2Buf = new byte[len];

		is.read(c2Buf);

		is.close();

		res[0] = c1Buf;
		res[1] = c2Buf;
		return res;
	}
	/**
	 * Return a ByteArrayOutputStream instead of writing to a file
	 */
	public static ByteArrayOutputStream writeCpabeData(byte[] mBuf,
			byte[] cphBuf, byte[] aesBuf) throws IOException {
		int i;
		ByteArrayOutputStream os = new ByteArrayOutputStream();
		/* write m_buf */
		for (i = 3; i >= 0; i--)
			os.write(((mBuf.length & (0xff << 8 * i)) >> 8 * i));
		os.write(mBuf);

		/* write aes_buf */
		for (i = 3; i >= 0; i--)
			os.write(((aesBuf.length & (0xff << 8 * i)) >> 8 * i));
		os.write(aesBuf);

		/* write cph_buf */
		for (i = 3; i >= 0; i--)
			os.write(((cphBuf.length & (0xff << 8 * i)) >> 8 * i));
		os.write(cphBuf);

		os.close();
		return os;
	}
	/**
	 * Read data from an InputStream instead of taking it from a file.
	 */
	public static byte[][] readCpabeData(InputStream is) throws IOException {
		int i, len;
		
		byte[][] res = new byte[3][];
		byte[] mBuf, aesBuf, cphBuf;

		/* read m buf */
		len = 0;
		for (i = 3; i >= 0; i--)
			len |= is.read() << (i * 8);
		mBuf = new byte[len];
		is.read(mBuf);
		/* read aes buf */
		len = 0;
		for (i = 3; i >= 0; i--)
			len |= is.read() << (i * 8);
		aesBuf = new byte[len];
		is.read(aesBuf);

		/* read cph buf */
		len = 0;
		for (i = 3; i >= 0; i--)
			len |= is.read() << (i * 8);
		cphBuf = new byte[len];
		is.read(cphBuf);

		is.close();
		res[0] = aesBuf;
		res[1] = cphBuf;
		res[2] = mBuf;
		return res;
	}
	
	public static byte[] serializeUsk(UencUsk usk) throws Exception
	{
		ArrayList<Byte> arrlist = new ArrayList<Byte>();
		
		serializeElement(arrlist, usk.g_pow_a);
		serializeElement(arrlist, usk.h_pow_x_divide_a);
	
		return Byte_arr2byte_arr(arrlist);
	}
	
	public static UencUsk unserializeUsk(byte[] b) {
		
		Pairing pairing = getPairing();
		
		UencUsk usk = new UencUsk();
		int offset = 0;
		
		usk.g_pow_a = pairing.getG1().newElement();
		usk.h_pow_x_divide_a = pairing.getG2().newElement();
	
		offset = unserializeElement(b, offset, usk.g_pow_a);
		offset = unserializeElement(b, offset, usk.h_pow_x_divide_a);
	
		return usk;
	}
	
	public static byte[] serializeUgp(UencUgp ugp) throws Exception
	{
		ArrayList<Byte> arrlist = new ArrayList<Byte>();
		
		serializeElement(arrlist, ugp.ugp);
		serializeElement(arrlist, ugp.g);
		serializeElement(arrlist, ugp.h);
	
		return Byte_arr2byte_arr(arrlist);
	}
	
	public static UencUgp unserializeUgp(byte[] b) throws Exception
	{
		Pairing pairing = getPairing();
		
		UencUgp ugp = new UencUgp();
		int offset = 0;
		
		ugp.ugp = pairing.getGT().newElement();
		ugp.g = pairing.getG1().newElement();
		ugp.h = pairing.getG2().newElement();
		
		offset = unserializeElement(b, offset, ugp.ugp);
		offset = unserializeElement(b, offset, ugp.g);
		offset = unserializeElement(b, offset, ugp.h);
		
		return ugp;
	}
	
	public static byte[] serializeX(Element x) throws Exception
	{
		ArrayList<Byte> arrlist = new ArrayList<Byte>();
		
		serializeElement(arrlist, x);
	
		return Byte_arr2byte_arr(arrlist);
	}
	
	public static Element unserializeX(byte[] b) throws Exception
	{
		Pairing pairing = getPairing();
		
		Element x = pairing.getZr().newElement();
		int offset = 0;
		
		offset = unserializeElement(b, offset, x);
		
		return x;
	}
	
	public static byte[] serializeRk(Element rk) throws Exception
	{
		ArrayList<Byte> arrlist = new ArrayList<Byte>();
		
		serializeElement(arrlist, rk);
	
		return Byte_arr2byte_arr(arrlist);
	}
	
	public static Element unserializeRk(byte[] b) throws Exception
	{
		Pairing pairing = getPairing();
		
		Element rk = pairing.getZr().newElement();
		int offset = 0;
		
		offset = unserializeElement(b, offset, rk);
		
		return rk;
	}
	
	public static Pairing getPairing()
	{
		CurveParameters params = new DefaultCurveParameters()
		.load(new ByteArrayInputStream(curveParams.getBytes()));
		return PairingFactory.getPairing(params);
	}
	
	public static void serializeElement(ArrayList<Byte> arrlist, Element e) {
		byte[] arr_e = e.toBytes();
		serializeUint32(arrlist, arr_e.length);
		byteArrListAppend(arrlist, arr_e);
	}

	/* Method has been test okay */
	public static int unserializeElement(byte[] arr, int offset, Element e) {
		int len;
		int i;
		byte[] e_byte;

		len = unserializeUint32(arr, offset);
		e_byte = new byte[(int) len];
		offset += 4;
		for (i = 0; i < len; i++)
			e_byte[i] = arr[offset + i];
		e.setFromBytes(e_byte);

		return (int) (offset + len);
	}

	public static void serializeString(ArrayList<Byte> arrlist, String s) {
		byte[] b = s.getBytes();
		serializeUint32(arrlist, b.length);
		byteArrListAppend(arrlist, b);
	}
	
	private static void serializeUint32(ArrayList<Byte> arrlist, int k) {
		int i;
		byte b;
	
		for (i = 3; i >= 0; i--) {
			b = (byte) ((k & (0x000000ff << (i * 8))) >> (i * 8));
			arrlist.add(Byte.valueOf(b));
		}
	}
	
	private static int unserializeUint32(byte[] arr, int offset) {
		int i;
		int r = 0;
	
		for (i = 3; i >= 0; i--)
			r |= (byte2int(arr[offset++])) << (i * 8);
		return r;
	}
	
	private static int byte2int(byte b) {
		if (b >= 0)
			return b;
		return (256 + b);
	}

	private static void byteArrListAppend(ArrayList<Byte> arrlist, byte[] b) {
		int len = b.length;
		for (int i = 0; i < len; i++)
			arrlist.add(Byte.valueOf(b[i]));
	}

	private static byte[] Byte_arr2byte_arr(ArrayList<Byte> B) {
		int len = B.size();
		byte[] b = new byte[len];
	
		for (int i = 0; i < len; i++)
			b[i] = B.get(i).byteValue();
	
		return b;
	}
}

package cpabe;
import java.net.URI;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FSDataInputStream;
import org.apache.hadoop.fs.FSDataOutputStream;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;

public class Common {

	/* read byte[] from inputfile */
	public static byte[] suckFile(String inputfile) throws Exception {
		
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
	public static void spitFile(String outputfile, byte[] b) throws Exception {
		
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


	public static void writeCpabeFile(String encfile,
			byte[] cphBuf, byte[] aesBuf) throws Exception {
		int i;
		
		Configuration conf = new Configuration(); 
        conf.set("hadoop.job.ugi", "hadoop-user,hadoop-user"); 
         
        FileSystem fs = FileSystem.get(URI.create(encfile),conf);
        FSDataOutputStream out = null;
        
        out = fs.create(new Path(encfile));
		
		/* write aes_buf */
		for (i = 3; i >= 0; i--)
			out.write(((aesBuf.length & (0xff << 8 * i)) >> 8 * i));
		out.write(aesBuf);

		/* write cph_buf */
		for (i = 3; i >= 0; i--)
			out.write(((cphBuf.length & (0xff << 8 * i)) >> 8 * i));
		out.write(cphBuf);

		out.close();
	}

	public static byte[][] readCpabeFile(String encfile) throws Exception {
		int i, len;
		
		Configuration conf = new Configuration(); 
        conf.set("hadoop.job.ugi", "hadoop-user,hadoop-user"); 
         
        FileSystem fs = FileSystem.get(URI.create(encfile),conf); 
        FSDataInputStream is = null; 
        is = fs.open( new Path(encfile) );
            
		byte[][] res = new byte[2][];
		byte[] aesBuf, cphBuf;

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
		return res;
	}
//	/**
//	 * Return a ByteArrayOutputStream instead of writing to a file
//	 */
//	public static ByteArrayOutputStream writeCpabeData(byte[] mBuf,
//			byte[] cphBuf, byte[] aesBuf) throws Exception {
//		int i;
//		
//		Configuration conf = new Configuration(); 
//        conf.set("hadoop.job.ugi", "hadoop-user,hadoop-user"); 
//         
//        FileSystem fs = FileSystem.get(URI.create(encfile),conf);
//        FSDataOutputStream out = null;
//        
//        out = fs.create(new Path(encfile));
//        
//		ByteArrayOutputStream os = new ByteArrayOutputStream();
//		/* write m_buf */
//		for (i = 3; i >= 0; i--)
//			os.write(((mBuf.length & (0xff << 8 * i)) >> 8 * i));
//		os.write(mBuf);
//
//		/* write aes_buf */
//		for (i = 3; i >= 0; i--)
//			os.write(((aesBuf.length & (0xff << 8 * i)) >> 8 * i));
//		os.write(aesBuf);
//
//		/* write cph_buf */
//		for (i = 3; i >= 0; i--)
//			os.write(((cphBuf.length & (0xff << 8 * i)) >> 8 * i));
//		os.write(cphBuf);
//
//		os.close();
//		return os;
//	}
//	/**
//	 * Read data from an InputStream instead of taking it from a file.
//	 */
//	public static byte[][] readCpabeData(InputStream is) throws IOException {
//		int i, len;
//		
//		byte[][] res = new byte[3][];
//		byte[] mBuf, aesBuf, cphBuf;
//
//		/* read m buf */
//		len = 0;
//		for (i = 3; i >= 0; i--)
//			len |= is.read() << (i * 8);
//		mBuf = new byte[len];
//		is.read(mBuf);
//		/* read aes buf */
//		len = 0;
//		for (i = 3; i >= 0; i--)
//			len |= is.read() << (i * 8);
//		aesBuf = new byte[len];
//		is.read(aesBuf);
//
//		/* read cph buf */
//		len = 0;
//		for (i = 3; i >= 0; i--)
//			len |= is.read() << (i * 8);
//		cphBuf = new byte[len];
//		is.read(cphBuf);
//
//		is.close();
//		res[0] = aesBuf;
//		res[1] = cphBuf;
//		res[2] = mBuf;
//		return res;
//	}
}

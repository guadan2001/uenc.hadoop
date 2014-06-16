package uenc_hadoop;

import java.io.File;
import java.io.IOException;

import org.apache.hadoop.conf.Configured;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.io.LongWritable;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.mapred.FileInputFormat;
import org.apache.hadoop.mapred.FileOutputFormat;
import org.apache.hadoop.mapred.JobClient;
import org.apache.hadoop.mapred.JobConf;
import org.apache.hadoop.mapred.MapReduceBase;
import org.apache.hadoop.mapred.Mapper;
import org.apache.hadoop.mapred.OutputCollector;
import org.apache.hadoop.mapred.Reporter;
import org.apache.hadoop.mapreduce.Mapper.Context;
import org.apache.hadoop.util.Tool;
import org.apache.hadoop.util.ToolRunner;

import uenc_application.CpabeTestStringBuilder;
import uenc_cpabe.UpdatableEncryption;
import cpabe.Cpabe;

public class UencEncHadoop extends Configured implements Tool {

	

	public static class CpAbeEncrypter extends MapReduceBase
    implements Mapper<LongWritable, Text, Text, Text> {

		public static String dataPath;
		public static String indexPath;
		public static String outputPath;
		
		public static int numofAttributes;
		public static int policyType;
		
		public void configure(JobConf job) {
		     dataPath = job.get("dataPath");
		     indexPath = job.get("indexPath");
		     outputPath = job.get("outputPath");
		     
		     numofAttributes = Integer.parseInt(job.get("numofAttributes"));
		     policyType = Integer.parseInt(job.get("policyType"));
		}

		@Override
		public void map(LongWritable key, Text value,
				OutputCollector<Text, Text> collector, Reporter reporter)
				throws IOException {
			
			String attrString = CpabeTestStringBuilder.getAttributesString(numofAttributes);
			String policy = CpabeTestStringBuilder.getPolicyString(numofAttributes,
					attrString, policyType);

			String resultPath = outputPath;

			String publicKey = dataPath + "single_keys" + File.separator + "pub_key";
			
			String uskFile = dataPath + "usk" + File.separator + value.toString() + ".usk";
			String ugpFile = dataPath + "single_keys" + File.separator + "ugp";

			String inputFile = dataPath + "src" + File.separator + value.toString();
			String encFileByAbe = resultPath + "cpabe" + File.separator + value.toString() + ".cpabe";
			String encFileByAbeUenc = resultPath + "cpabe.uenc" + File.separator + value.toString()
					+ ".cpabe.uenc";

			Cpabe cpabe = new Cpabe();
			UpdatableEncryption uenc = new UpdatableEncryption();

			try {
				cpabe.enc(publicKey, policy, inputFile, encFileByAbe);
				uenc.uEncrypt(ugpFile, uskFile, encFileByAbe, encFileByAbeUenc);

			} catch (Exception e) {
				collector.collect(new Text(e.toString()), new Text(""));
			}
			
		}
	}

	public static void main(String args[]) throws Exception {
		ToolRunner.run(new UencEncHadoop(), args);
	}

	public int run(String[] args) throws Exception {
		
		JobConf job = new JobConf(getConf());

		if (args.length != 6 || args[0] == "-h") {
			System.err
					.println("Usage: uenc_enc_hadoop <index-folder> <input-folder> <out-folder> <numof-map-tasks> <numof-attributes> <policy-type>");
			System.exit(2);
		}

		//modify these parameters before running
		job.set("mapred.job.tracker", "hadoop-master:9001");
		job.set("fs.default.name", "hdfs://hadoop-master:9000/");
		
		job.setJobName("uenc_enc_hadoop");
		job.setJarByClass(UencEncHadoop.class);
		job.setMapperClass(CpAbeEncrypter.class);
		job.setOutputKeyClass(Text.class);
		job.setOutputValueClass(Text.class);
		job.setNumMapTasks(Integer.parseInt(args[3]));
		job.setNumReduceTasks(0);
		FileInputFormat.setInputPaths(job, new Path(args[0]));
		FileOutputFormat.setOutputPath(job, new Path(args[2]));
		job.set("indexPath", args[0] + File.separator);
		job.set("dataPath", args[1] + File.separator);
		job.set("outputPath", args[2] + File.separator);
		job.set("numofAttributes", args[4]);
		job.set("policyType", args[5]);
		
		JobClient.runJob(job);

		return 0;
	}
}

Implementation of Updatable Encryption in Hadoop

Description:
The project contains 3 apps: uenc_enc_hadoop, uenc_dec_hadoop, uenc_update_hadoop.

Hadoop version: 
0.20.205.0

Data Preparation:
1. uenc_enc_hadoop:
	1) Copy the index file into HDFS://<index-folder>
	2) Copy the pub_key, ugp file into HDFS://<input-folder>/single_keys
	3) Copy the usk files into HDFS://<input-folder>/usk
	4) Copy the sample files into HDFS://<input-folder>/src
	5) Create a Directory: HDFS://<out-folder>/rk
	6) Create a Directory: HDFS://<out-folder>/cpabe.uenc
2. uenc_dec_hadoop:
	1) Copy the index file into HDFS://<index-folder>
	2) Copy the pub_key, prv_key file into HDFS://<input-folder>/single_keys
	3) Copy the encrypted files into HDFS://<input-folder>/cpabe.uenc
	4) Copy the usk files into HDFS://<input-folder>/usk
	5) Create a Directory: HDFS://<out-folder>/dec_by_uenc
	6) Create a Directory: HDFS://<out-folder>/dec_by_cpabe
3. uenc_update_hadoop:
	1) Copy the index file into HDFS://<index-folder>
	2) Copy the encrypted files into HDFS://<input-folder>/cpabe.uenc
	3) Copy the usk files into HDFS://<input-folder>/usk
	4) Create a Directory: HDFS://<out-folder>/rk
	5) Create a Directory: HDFS://<out-folder>/new_usk
	6) Create a Directory: HDFS://<out-folder>/cpabe.uenc.updated

Usage:
uenc_enc_hadoop <index-folder> <input-folder> <out-folder> <numof-map-tasks> <numof-attributes> <policy-type>
uenc_dec_hadoop <index-folder> <input-folder> <out-folder> <numof-map-tasks>
uenc_update_hadoop <index-folder> <input-folder> <out-folder> <numof-map-tasks> <numof-attributes>

NOTICE:
Modifying the JobTracker Address and HDFS Address in UencEncHadoop.java, UencDecHadoop.java and UencUpdateHadoop.java before running.

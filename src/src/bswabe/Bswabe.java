package bswabe;

import it.unisa.dia.gas.jpbc.CurveParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.DefaultCurveParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.io.ByteArrayInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.RecursiveAction;
import java.util.concurrent.TimeUnit;

public class Bswabe {

	private static final int THRESHOLD = 5;
	/*
	 * Generate a public key and corresponding master secret key.
	 */

//	private static String curveParams = "type f\n"
//			+ "q 205523667896953300194896352429254920972540065223\n"
//			+ "r 205523667896953300194895899082072403858390252929\n"
//			+ "b 40218105156867728698573668525883168222119515413\n"
//			+ "beta 115334401956802802075595682801335644058796914268\n"
//			+ "alpha0 191079354656274778837764015557338301375963168470\n"
//			+ "alpha1 71445317903696340296199556072836940741717506375\n";
	
	private static String curveParams = "type a\n"
	+ "q 87807107996633125224377819847540498158068831994142082"
	+ "1102865339926647563088022295707862517942266222142315585"
	+ "8769582317459277713367317481324925129998224791\n"
	+ "h 12016012264891146079388821366740534204802954401251311"
	+ "822919615131047207289359704531102844802183906537786776\n"
	+ "r 730750818665451621361119245571504901405976559617\n"
	+ "exp2 159\n" + "exp1 107\n" + "sign1 1\n" + "sign0 1\n";

	public static void setup(BswabePub pub, BswabeMsk msk) {
		Element alpha, beta_inv;

		CurveParameters params = new DefaultCurveParameters()
				.load(new ByteArrayInputStream(curveParams.getBytes()));

		pub.pairingDesc = curveParams;
		pub.p = PairingFactory.getPairing(params);
		Pairing pairing = pub.p;

		pub.g = pairing.getG1().newElement();
		pub.f = pairing.getG1().newElement();
		pub.h = pairing.getG1().newElement();
		pub.gp = pairing.getG2().newElement();
		pub.g_hat_alpha = pairing.getGT().newElement();
		alpha = pairing.getZr().newElement();
		msk.beta = pairing.getZr().newElement();
		msk.g_alpha = pairing.getG2().newElement();

		alpha.setToRandom();
		msk.beta.setToRandom();
		pub.g.setToRandom();
		pub.gp.setToRandom();

		msk.g_alpha = pub.gp.duplicate();
		msk.g_alpha.powZn(alpha);

		beta_inv = msk.beta.duplicate();
		beta_inv.invert();
		pub.f = pub.g.duplicate();
		pub.f.powZn(beta_inv);

		pub.h = pub.g.duplicate();
		pub.h.powZn(msk.beta);

		pub.g_hat_alpha = pairing.pairing(pub.g, msk.g_alpha);
	}

	/*
	 * Generate a private key with the given set of attributes.
	 */
	public static BswabePrv keygen(BswabePub pub, BswabeMsk msk, String[] attrs)
			throws NoSuchAlgorithmException {
		BswabePrv prv = new BswabePrv();
		Element g_r, r, beta_inv;
		Pairing pairing;

		/* initialize */
		pairing = pub.p;
		prv.d = pairing.getG2().newElement();
		g_r = pairing.getG2().newElement();
		r = pairing.getZr().newElement();
		beta_inv = pairing.getZr().newElement();

		System.err.println("G1 Length:" + pairing.getG1().getLengthInBytes()
				* 8 + " bits");
		System.err.println("G2 Length:" + pairing.getG2().getLengthInBytes()
				* 8 + " bits");

		/* compute */
		r.setToRandom();
		g_r = pub.gp.duplicate();
		g_r.powZn(r);

		prv.d = msk.g_alpha.duplicate();
		prv.d.mul(g_r);
		beta_inv = msk.beta.duplicate();
		beta_inv.invert();
		prv.d.powZn(beta_inv);

		int len = attrs.length;
		prv.comps = new ArrayList<BswabePrvComp>();

		for (int i = 0; i < len; i++) {
			prv.comps.add(new BswabePrvComp());
		}

		System.out.println("Attributes List Length: " + String.valueOf(len));
		// TODO: parallelize here
		ForkJoinPool fjp = new ForkJoinPool();
		fjp.submit(new KeyGenTask(0, len, attrs, pairing, pub, g_r, prv));
		fjp.shutdown();
		try {
			fjp.awaitTermination(30, TimeUnit.SECONDS);
		} catch (InterruptedException e) {
			e.printStackTrace();
		}

		// for (int i = 0; i < len; i++) {
		// BswabePrvComp comp = new BswabePrvComp();
		// Element h_rp;
		// Element rp;
		//
		// comp.attr = attrs[i];
		//
		// comp.d = pairing.getG2().newElement();
		// comp.dp = pairing.getG1().newElement();
		// h_rp = pairing.getG2().newElement();
		// rp = pairing.getZr().newElement();
		//
		// elementFromString(h_rp, comp.attr);
		// rp.setToRandom();
		//
		// h_rp.powZn(rp);
		//
		// comp.d = g_r.duplicate();
		// comp.d.mul(h_rp);
		// comp.dp = pub.g.duplicate();
		// comp.dp.powZn(rp);
		//
		// prv.comps.add(comp);
		// }

		// for(int i = 0; i< prv.comps.size(); i++)
		// {
		// System.out.println(prv.comps.get(i).attr + " / " +
		// prv.comps.get(i).z);
		// }

		return prv;
	}

	private static class KeyGenTask extends RecursiveAction {
		private int start;
		private int end;
		private String[] attrs;
		private Pairing pairing;
		private BswabePub pub;
		private Element g_r;
		private BswabePrv prv;

		public KeyGenTask(int start, int end, String[] attrs, Pairing pairing,
				BswabePub pub, Element g_r, BswabePrv prv) {
			this.start = start;
			this.end = end;
			this.attrs = attrs;
			this.pairing = pairing;
			this.pub = pub;
			this.g_r = g_r;
			this.prv = prv;
		}

		@Override
		protected void compute() {
			if ((end - start) < THRESHOLD) {
				for (int i = start; i <= end; i++) {
					BswabePrvComp comp = new BswabePrvComp();
					Element h_rp;
					Element rp;

					comp.attr = attrs[i];

					comp.d = pairing.getG2().newElement();
					comp.dp = pairing.getG1().newElement();
					h_rp = pairing.getG2().newElement();
					rp = pairing.getZr().newElement();

					try {
						elementFromString(h_rp, comp.attr);
					} catch (NoSuchAlgorithmException e) {
						e.printStackTrace();
					}
					rp.setToRandom();

					h_rp.powZn(rp);

					comp.d = g_r.duplicate();
					comp.d.mul(h_rp);
					comp.dp = pub.g.duplicate();
					comp.dp.powZn(rp);

					// prv.comps.add(comp);
					prv.comps.set(i, comp);
				}
			} else {
				int middle = (start + end) / 2;
				KeyGenTask left = new KeyGenTask(start, middle, attrs, pairing,
						pub, g_r, prv);
				KeyGenTask right = new KeyGenTask(middle + 1, end, attrs,
						pairing, pub, g_r, prv);
				left.fork();
				right.fork();
			}
		}
	}

	/*
	 * Delegate a subset of attribute of an existing private key.
	 */
	public static BswabePrv delegate(BswabePub pub, BswabePrv prv_src,
			String[] attrs_subset) throws NoSuchAlgorithmException,
			IllegalArgumentException {

		BswabePrv prv = new BswabePrv();
		Element g_rt, rt, f_at_rt;
		Pairing pairing;

		/* initialize */
		pairing = pub.p;
		prv.d = pairing.getG2().newElement();

		g_rt = pairing.getG2().newElement();
		rt = pairing.getZr().newElement();
		f_at_rt = pairing.getZr().newElement();

		/* compute */
		rt.setToRandom();
		f_at_rt = pub.f.duplicate();
		f_at_rt.powZn(rt);
		prv.d = prv_src.d.duplicate();
		prv.d.mul(f_at_rt);

		g_rt = pub.g.duplicate();
		g_rt.powZn(rt);

		int i, len = attrs_subset.length;
		prv.comps = new ArrayList<BswabePrvComp>();

		for (i = 0; i < len; i++) {
			BswabePrvComp comp = new BswabePrvComp();
			Element h_rtp;
			Element rtp;

			comp.attr = attrs_subset[i];

			BswabePrvComp comp_src = new BswabePrvComp();
			boolean comp_src_init = false;

			for (int j = 0; j < prv_src.comps.size(); ++j) {
				if (prv_src.comps.get(j).attr == comp.attr) {
					comp_src = prv_src.comps.get(j);
					comp_src_init = true;
					break;
				}
			}

			if (comp_src_init == false) {
				throw new IllegalArgumentException("comp_src_init == false");
			}

			comp.d = pairing.getG2().newElement();
			comp.dp = pairing.getG1().newElement();
			h_rtp = pairing.getG2().newElement();
			rtp = pairing.getZr().newElement();

			elementFromString(h_rtp, comp.attr);
			rtp.setToRandom();

			h_rtp.powZn(rtp);

			comp.d = g_rt.duplicate();
			comp.d.mul(h_rtp);
			comp.d.mul(comp_src.d);

			comp.dp = pub.g.duplicate();
			comp.dp.powZn(rtp);
			comp.dp.mul(comp_src.dp);

			prv.comps.add(comp);
		}

		return prv;
	}

	/*
	 * Pick a random group element and encrypt it under the specified access
	 * policy. The resulting ciphertext is returned and the Element given as an
	 * argument (which need not be initialized) is set to the random group
	 * element.
	 * 
	 * After using this function, it is normal to extract the random data in m
	 * using the pbc functions element_length_in_bytes and element_to_bytes and
	 * use it as a key for hybrid encryption.
	 * 
	 * The policy is specified as a simple string which encodes a postorder
	 * traversal of threshold tree defining the access policy. As an example,
	 * 
	 * "foo bar fim 2of3 baf 1of2"
	 * 
	 * specifies a policy with two threshold gates and four leaves. It is not
	 * possible to specify an attribute with whitespace in it (although "_" is
	 * allowed).
	 * 
	 * Numerical attributes and any other fancy stuff are not supported.
	 * 
	 * Returns null if an error occured, in which case a description can be
	 * retrieved by calling bswabe_error().
	 */
	public static BswabeCphKey enc(BswabePub pub, String policy)
			throws Exception {
		BswabeCphKey keyCph = new BswabeCphKey();
		BswabeCph cph = new BswabeCph();
		Element s, m;

		/* initialize */

		Pairing pairing = pub.p;
		s = pairing.getZr().newElement();
		m = pairing.getGT().newElement();
		cph.cs = pairing.getGT().newElement();
		cph.c = pairing.getG1().newElement();
		cph.p = parsePolicyPostfix(policy);

		/* compute */
		m.setToRandom();
		s.setToRandom();
		// m.set(100);
		// s.set(200);
		cph.cs = pub.g_hat_alpha.duplicate();
		cph.cs.powZn(s); /* num_exps++; */
		cph.cs.mul(m); /* num_muls++; */

		cph.c = pub.h.duplicate();
		cph.c.powZn(s); /* num_exps++; */

		// fillPolicy(cph.p, pub, s);

		ForkJoinPool fjp = new ForkJoinPool();
		fjp.submit(new FillPolicyTask(cph.p, pub, s));
		fjp.shutdown();
		fjp.awaitTermination(30, TimeUnit.SECONDS);

		keyCph.cph = cph;
		keyCph.key = m;

		return keyCph;
	}

	/*
	 * Decrypt the specified ciphertext using the given private key, filling in
	 * the provided element m (which need not be initialized) with the result.
	 * 
	 * Returns true if decryption succeeded, false if this key does not satisfy
	 * the policy of the ciphertext (in which case m is unaltered).
	 */
	public static BswabeElementBoolean dec(BswabePub pub, BswabePrv prv,
			BswabeCph cph) throws Exception {
		Element t;
		Element m;
		BswabeElementBoolean beb = new BswabeElementBoolean();

		m = pub.p.getGT().newElement();
		t = pub.p.getGT().newElement();

		checkSatisfy(cph.p, prv);
		if (!cph.p.satisfiable) {
			System.err
					.println("cannot decrypt, attributes in key do not satisfy policy");
			beb.e = null;
			beb.b = false;
			return beb;
		}

		pickSatisfyMinLeaves(cph.p, prv);

		// decFlatten(t, cph.p, prv, pub);
		decFlattenOptimized(t, cph.p, prv, pub);

		m = cph.cs.duplicate();
		m.mul(t); /* num_muls++; */

		t = pub.p.pairing(cph.c, prv.d);
		t.invert();
		m.mul(t); /* num_muls++; */

		beb.e = m;
		beb.b = true;

		return beb;
	}

	private static void decFlatten(Element r, BswabePolicy p, BswabePrv prv,
			BswabePub pub) {
		Element one;
		one = pub.p.getZr().newElement();
		one.setToOne();
		r.setToOne();

		decNodeFlatten(r, one, p, prv, pub);
	}

	private static void decFlattenOptimized(Element r, BswabePolicy p,
			BswabePrv prv, BswabePub pub) throws Exception {
		Element one;
		one = pub.p.getZr().newElement();
		one.setToOne();
		r.setToOne();

		ForkJoinPool fjp = new ForkJoinPool();
		fjp.submit(new DecNodeFlattenTask(r, one, p, prv, pub));
		fjp.shutdown();
		fjp.awaitTermination(30, TimeUnit.SECONDS);

	}

	private static void decNodeFlatten(Element r, Element exp, BswabePolicy p,
			BswabePrv prv, BswabePub pub) {
		if (p.children == null || p.children.length == 0)
			decLeafFlatten(r, exp, p, prv, pub);
		else
			decInternalFlatten(r, exp, p, prv, pub);
	}

	private static void decLeafFlatten(Element r, Element exp, BswabePolicy p,
			BswabePrv prv, BswabePub pub) {
		BswabePrvComp c;
		Element s, t;

		c = prv.comps.get(p.attri);

		s = pub.p.getGT().newElement();
		t = pub.p.getGT().newElement();

		s = pub.p.pairing(p.c, c.d); /* num_pairings++; */
		t = pub.p.pairing(p.cp, c.dp); /* num_pairings++; */
		t.invert();
		s.mul(t); /* num_muls++; */
		s.powZn(exp); /* num_exps++; */

		r.mul(s); /* num_muls++; */
	}

	private static void decInternalFlatten(Element r, Element exp,
			BswabePolicy p, BswabePrv prv, BswabePub pub) {
		int i;
		Element t, expnew;

		t = pub.p.getZr().newElement();
		expnew = pub.p.getZr().newElement();

		for (i = 0; i < p.satl.size(); i++) {
			lagrangeCoef(t, p.satl, (p.satl.get(i)).intValue());
			expnew = exp.duplicate();
			expnew.mul(t);
			decNodeFlatten(r, expnew, p.children[p.satl.get(i) - 1], prv, pub);
		}
	}

	private static class DecNodeFlattenTask extends RecursiveAction {
		private Element r;
		private Element exp;
		private BswabePolicy p;
		private BswabePrv prv;
		private BswabePub pub;

		public DecNodeFlattenTask(Element r, Element exp, BswabePolicy p,
				BswabePrv prv, BswabePub pub) {
			this.r = r;
			this.exp = exp;
			this.p = p;
			this.prv = prv;
			this.pub = pub;
		}

		@Override
		protected void compute() {

			if (p.children == null || p.children.length == 0) {
				BswabePrvComp c;
				Element s, t;

				c = prv.comps.get(p.attri);

				s = pub.p.getGT().newElement();
				t = pub.p.getGT().newElement();

				s = pub.p.pairing(p.c, c.d); /* num_pairings++; */
				t = pub.p.pairing(p.cp, c.dp); /* num_pairings++; */
				t.invert();
				s.mul(t); /* num_muls++; */
				s.powZn(exp); /* num_exps++; */

				r.mul(s); /* num_muls++; */
			} else {
				Element t, expnew;

				t = pub.p.getZr().newElement();
				expnew = pub.p.getZr().newElement();

				for (int i = 0; i < p.satl.size(); i++) {
					lagrangeCoef(t, p.satl, (p.satl.get(i)).intValue());
					expnew = exp.duplicate();
					expnew.mul(t);
					new DecNodeFlattenTask(r, expnew,
							p.children[p.satl.get(i) - 1], prv, pub).fork();
				}
			}

		}
	}

	private static void lagrangeCoef(Element r, ArrayList<Integer> s, int i) {
		int j, k;
		Element t;

		t = r.duplicate();

		r.setToOne();
		for (k = 0; k < s.size(); k++) {
			j = s.get(k).intValue();
			if (j == i)
				continue;
			t.set(-j);
			r.mul(t); /* num_muls++; */
			t.set(i - j);
			t.invert();
			r.mul(t); /* num_muls++; */
		}
	}

	private static void pickSatisfyMinLeaves(BswabePolicy p, BswabePrv prv) {
		int i, k, l, c_i;
		int len;
		ArrayList<Integer> c = new ArrayList<Integer>();

		if (p.children == null || p.children.length == 0)
			p.min_leaves = 1;
		else {
			len = p.children.length;
			for (i = 0; i < len; i++)
				if (p.children[i].satisfiable)
					pickSatisfyMinLeaves(p.children[i], prv);

			for (i = 0; i < len; i++)
				c.add(new Integer(i));

			Collections.sort(c, new IntegerComparator(p));

			p.satl = new ArrayList<Integer>();
			p.min_leaves = 0;
			l = 0;

			for (i = 0; i < len && l < p.k; i++) {
				c_i = c.get(i).intValue(); /* c[i] */
				if (p.children[c_i].satisfiable) {
					l++;
					p.min_leaves += p.children[c_i].min_leaves;
					k = c_i + 1;
					p.satl.add(new Integer(k));
				}
			}
		}
	}

	private static void checkSatisfy(BswabePolicy p, BswabePrv prv) {
		int i, l;
		String prvAttr;
		// TODO: parallelize here
		p.satisfiable = false;
		if (p.children == null || p.children.length == 0) {
			for (i = 0; i < prv.comps.size(); i++) {
				prvAttr = prv.comps.get(i).attr;
				// System.out.println("prvAtt:" + prvAttr);
				// System.out.println("p.attr" + p.attr);
				if (prvAttr.compareTo(p.attr) == 0) {
					// System.out.println("=satisfy=");
					p.satisfiable = true;
					p.attri = i;
					break;
				}
			}
		} else {
			for (i = 0; i < p.children.length; i++)
				checkSatisfy(p.children[i], prv);

			l = 0;
			for (i = 0; i < p.children.length; i++)
				if (p.children[i].satisfiable)
					l++;

			if (l >= p.k)
				p.satisfiable = true;
		}
	}

	private static void fillPolicy(BswabePolicy p, BswabePub pub, Element e)
			throws NoSuchAlgorithmException {
		int i;
		Element r, t, h;
		Pairing pairing = pub.p;
		r = pairing.getZr().newElement();
		t = pairing.getZr().newElement();
		h = pairing.getG2().newElement();

		p.q = randPoly(p.k - 1, e);
		if (p.children == null || p.children.length == 0) {
			System.out.println("LEAF" + " - " + e.toString());
			p.c = pairing.getG1().newElement();
			p.cp = pairing.getG2().newElement();

			elementFromString(h, p.attr);
			p.c = pub.g.duplicate();
			p.c.powZn(p.q.coef[0]);
			p.cp = h.duplicate();
			p.cp.powZn(p.q.coef[0]);
			System.out.println(p.attr + " / " + p.cp.toString());
		} else {
			System.out.println("NODE / parentof(" + p.children[1].attr + ") - "
					+ e.toString());
			for (i = 0; i < p.children.length; i++) {
				r.set(i + 1);
				evalPoly(t, p.q, r);
				fillPolicy(p.children[i], pub, t);
			}
		}
	}

	private static class FillPolicyTask extends RecursiveAction {
		private BswabePolicy p;
		private BswabePub pub;
		private Element e;

		public FillPolicyTask(BswabePolicy p, BswabePub pub, Element e) {
			this.p = p;
			this.pub = pub;
			this.e = e;
		}

		@Override
		protected void compute() {
			int i;
			Element r, h;
			Pairing pairing = pub.p;
			r = pairing.getZr().newElement();
			h = pairing.getG2().newElement();

			p.q = randPoly(p.k - 1, e);
			// TODO: parallelize here
			if (p.children == null || p.children.length == 0) {
				// System.out.println("LEAF / " + p.attr + " - " + e.toString()
				// + " - " + System.identityHashCode(e) + " - "
				// + Thread.currentThread().getName());
				p.c = pairing.getG1().newElement();
				p.cp = pairing.getG2().newElement();

				try {
					elementFromString(h, p.attr);
				} catch (NoSuchAlgorithmException e1) {
					e1.printStackTrace();
				}
				p.c = pub.g.duplicate();
				p.c.powZn(p.q.coef[0]);
				p.cp = h.duplicate();
				p.cp.powZn(p.q.coef[0]);
			} else {
				// System.out.println("NODE / parentof(" + p.children[1].attr
				// + ") - " + e.toString() + " - "
				// + System.identityHashCode(e) + " - "
				// + Thread.currentThread().getName());
				for (i = 0; i < p.children.length; i++) {
					Element t;
					t = pairing.getZr().newElement();
					r.set(i + 1);
					evalPoly(t, p.q, r);
					new FillPolicyTask(p.children[i], pub, t).fork();
				}
			}
		}
	}

	private static void evalPoly(Element r, BswabePolynomial q, Element x) {
		int i;
		Element s, t;

		s = r.duplicate();
		t = r.duplicate();

		r.setToZero();
		t.setToOne();

		for (i = 0; i < q.deg + 1; i++) {
			/* r += q->coef[i] * t */
			s = q.coef[i].duplicate();
			s.mul(t);
			r.add(s);

			/* t *= x */
			t.mul(x);
		}

	}

	private static BswabePolynomial randPoly(int deg, Element zeroVal) {
		int i;
		BswabePolynomial q = new BswabePolynomial();
		q.deg = deg;
		q.coef = new Element[deg + 1];

		for (i = 0; i < deg + 1; i++)
			q.coef[i] = zeroVal.duplicate();

		q.coef[0].set(zeroVal);

		for (i = 1; i < deg + 1; i++)
			q.coef[i].setToRandom();
		// q.coef[i].set(1);

		return q;
	}

	private static BswabePolicy parsePolicyPostfix(String s) throws Exception {
		String[] toks;
		String tok;
		ArrayList<BswabePolicy> stack = new ArrayList<BswabePolicy>();
		BswabePolicy root;

		toks = s.split(" ");

		int toks_cnt = toks.length;
		for (int index = 0; index < toks_cnt; index++) {
			int i, k, n;

			tok = toks[index];
			if (!tok.contains("of")) {
				stack.add(baseNode(1, tok));
			} else {
				BswabePolicy node;

				/* parse kof n node */
				String[] k_n = tok.split("of");
				k = Integer.parseInt(k_n[0]);
				n = Integer.parseInt(k_n[1]);

				if (k < 1) {
					System.out.println("error parsing " + s
							+ ": trivially satisfied operator " + tok);
					return null;
				} else if (k > n) {
					System.out.println("error parsing " + s
							+ ": unsatisfiable operator " + tok);
					return null;
				} else if (n == 1) {
					System.out.println("error parsing " + s
							+ ": indentity operator " + tok);
					return null;
				} else if (n > stack.size()) {
					System.out.println("error parsing " + s
							+ ": stack underflow at " + tok);
					return null;
				}

				/* pop n things and fill in children */
				node = baseNode(k, null);
				node.children = new BswabePolicy[n];

				for (i = n - 1; i >= 0; i--)
					node.children[i] = stack.remove(stack.size() - 1);

				/* push result */
				stack.add(node);
			}
		}

		if (stack.size() > 1) {
			System.out.println("error parsing " + s
					+ ": extra node left on the stack");
			return null;
		} else if (stack.size() < 1) {
			System.out.println("error parsing " + s + ": empty policy");
			return null;
		}

		root = stack.get(0);
		return root;
	}

	private static BswabePolicy baseNode(int k, String s) {
		BswabePolicy p = new BswabePolicy();

		p.k = k;
		if (!(s == null))
			p.attr = s;
		else
			p.attr = null;
		p.q = null;

		return p;
	}

	private static void elementFromString(Element h, String s)
			throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("SHA-1");
		byte[] digest = md.digest(s.getBytes());
		h.setFromHash(digest, 0, digest.length);
	}

	private static class IntegerComparator implements Comparator<Integer> {
		BswabePolicy policy;

		public IntegerComparator(BswabePolicy p) {
			this.policy = p;
		}

		@Override
		public int compare(Integer o1, Integer o2) {
			int k, l;

			k = policy.children[o1.intValue()].min_leaves;
			l = policy.children[o2.intValue()].min_leaves;

			return k < l ? -1 : k == l ? 0 : 1;
		}
	}
}

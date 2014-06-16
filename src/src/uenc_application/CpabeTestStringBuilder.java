package uenc_application;

import java.util.Random;
import java.util.Stack;

public class CpabeTestStringBuilder {

	private static final int CHILDREN_MAX = 5;

	public static final int POLICY_RANDOM = 0;
	public static final int POLICY_AND_ALL = 1;
	public static final int POLICY_OR_ALL = 2;

	public static String getAttributesString(int numOfAttributes) {
		String attr_str = "attr1:obj";

		for (int i = 1; i < numOfAttributes; i++) {
			attr_str = attr_str + " attr" + String.valueOf(i + 1) + ":obj";
		}
		return attr_str;
	}

	public static String getPolicyString(int numOfLeafNodesMax,
			String attributeString, int policyType) {
		String policyString = "";

		String[] attributeArray = attributeString.split(" ");
		
		Stack<String> s = new Stack<String>();

		for (int i = numOfLeafNodesMax - 1; i >= 0; i--) {
			s.push(attributeArray[i]);
		}

		while (true) {
			Random r = new Random();
			int selected = r.nextInt(CHILDREN_MAX - 2) + 2;

			if (s.size() <= selected) {
				selected = s.size();
			}

			for (int i = 0; i < selected; i++) {
				policyString = policyString + s.pop() + " ";
			}

			String policyNode = getPolicyNode(selected, policyType);
			s.push(policyNode);

			if (s.size() == 1) {
				policyString = policyString + s.pop();
				break;
			}
		}

		return policyString;
	}

	private static String getPolicyNode(int numOfLeafNodes, int policyType) {
		
		int selected = 0;
		
		switch(policyType)
		{
		case CpabeTestStringBuilder.POLICY_RANDOM:
			Random r = new Random();
			selected = r.nextInt(numOfLeafNodes) + 1;
			break;
		case CpabeTestStringBuilder.POLICY_AND_ALL:
			selected = numOfLeafNodes;
			break;
		case CpabeTestStringBuilder.POLICY_OR_ALL:
			selected = 1;
			break;
		}
		
		return String.valueOf(selected) + "of" + String.valueOf(numOfLeafNodes);
	}

}
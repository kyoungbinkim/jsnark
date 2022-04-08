package examples.gadgets.hash;

import java.security.cert.TrustAnchor;

import circuit.config.Config;
import circuit.operations.Gadget;
import circuit.structure.Wire;
import circuit.structure.WireArray;


public class MerkleTreePathGadgetSha2 extends Gadget {
    private static int digestWidth = 8;

	private int treeHeight;
	private Wire directionSelectorWire;
	private Wire[] directionSelectorBits;
	private Wire leafWire;
	private Wire[] intermediateHashWires;
	private Wire[] outRoot;

	private int leafBitWidth;

	public MerkleTreePathGadgetSha2(Wire directionSelectorWire, Wire leafWire, Wire[] intermediateHasheWires,
			int leafBitWidth, int treeHeight, String... desc) {

		super(desc);
		this.directionSelectorWire = directionSelectorWire;
		this.treeHeight = treeHeight;
		this.leafWire = leafWire;
		this.intermediateHashWires = intermediateHasheWires;
		this.leafBitWidth = leafBitWidth;

		buildCircuit();

	}

	private void buildCircuit() {

		directionSelectorBits = directionSelectorWire.getBitWires(treeHeight).asArray();
		
		// Apply CRH to leaf data
		Wire[] leafBits = leafWire.getBitWires(leafBitWidth).asArray();
		SHA256Gadget sha2gadget = new SHA256Gadget(leafBits,1, leafBitWidth/8, false, true);
		Wire[] currentHash = sha2gadget.getOutputWires(); // first, calculate currentHash = CRH(leaf)

		// Apply CRH across tree path guided by the direction bits
		for (int i = 0; i < treeHeight; i++) {
			
			Wire[] inHash = new Wire[2 * digestWidth]; // 16

			for (int j = 0; j < digestWidth; j++) {
				Wire temp = currentHash[j].sub(intermediateHashWires[i * digestWidth + j]);
				Wire temp2 = directionSelectorBits[i].mul(temp);
				inHash[j] = intermediateHashWires[i * digestWidth + j].add(temp2);
			}
			for (int j = digestWidth; j < 2 * digestWidth; j++) {
				Wire temp = currentHash[j - digestWidth].add(intermediateHashWires[i * digestWidth + j - digestWidth]);
				inHash[j] = temp.sub(inHash[j - digestWidth]);
			}

			/*
			if directionSelector == 0:
			 inHash = intermediateHas` || currentHash
			else:
			 inHash = currentHash || intermediateHash
			*/
			

			Wire[] nextInputBits = new WireArray(inHash).getBits(32).asArray();
			sha2gadget = new SHA256Gadget(nextInputBits, 1, 64, false, true); // totalByte : 32 * 16 / 8
			currentHash = sha2gadget.getOutputWires(); 
			 
		}
		outRoot = currentHash;
	}

	@Override
	public Wire[] getOutputWires() {
		return outRoot;
	}
}

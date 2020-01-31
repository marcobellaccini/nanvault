require "./spec_helper"

describe Nanvault do
  # TODO: Write tests

  describe Nanvault::Encrypted do
    describe "#initialize" do
      it "correctly loads header and body" do
        enc = Nanvault::Encrypted.new ["HEADER", "BODY1", "BODY2"]
        enc.header.should eq("HEADER")
        enc.body.should eq("BODY1BODY2")
      end
    end
  end

end

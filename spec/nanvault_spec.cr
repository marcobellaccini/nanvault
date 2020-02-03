require "./spec_helper"

describe Nanvault do
  # TODO: Write tests

  describe Nanvault::Encrypted do

    header_ok = "$ANSIBLE_VAULT;1.1;AES256"

    body_ok = "34393465386232383131386237626532306236396636396135393664323834383838313035666331" \
              "6564353662313632616133366237393830393036303833320a356631363739393737316664313765" \
              "63336362376661303365386566363361306630323639326161313166613564363561306133643662" \
              "6466666165383365640a646365656164633362346630396335396365313231303238643039303937" \
              "64393735663933666330366466393366376164306531313238393334633266646165"

    body_ok_bytes = body_ok.hexbytes

    describe "#initialize" do
      it "correctly loads header and body" do
        enc = Nanvault::Encrypted.new ["HEADER", "BODY1", "BODY2"]
        enc.header.should eq("HEADER")
        enc.body.should eq("BODY1BODY2")
      end

      it "correctly handles empty array" do
        expect_raises(Nanvault::BadFile, "Invalid input file") do
          enc = Nanvault::Encrypted.new Array(String).new
        end
      end

      it "correctly handles header-only file" do
        expect_raises(Nanvault::BadFile, "Invalid input file") do
          enc = Nanvault::Encrypted.new ["HEADER"]
        end
      end

      it "load real file" do
        enc_str = File.read_lines("spec/testfiles/test1.enc")
        enc = Nanvault::Encrypted.new enc_str
        enc.header.should eq(header_ok)
        enc.body.should eq body_ok
      end
    end
    describe "#parse" do
      it "correctly parse ok header" do
        head = "$ANSIBLE_VAULT;1.2;AES256;vault-id-label"
        enc = Nanvault::Encrypted.new [head, body_ok]
        enc.parse
        exp_vault_info = {"version" => "1.2", "alg" => "AES256", "label" => "vault-id-label"}
        enc.vault_info.should eq exp_vault_info
      end

      it "correctly parse ok-nolabel header" do
        head = "$ANSIBLE_VAULT;1.1;AES256"
        enc = Nanvault::Encrypted.new [head, body_ok]
        enc.parse
        exp_vault_info = {"version" => "1.1", "alg" => "AES256", "label" => nil}
        enc.vault_info.should eq exp_vault_info
      end

      it "correctly handles incomplete header" do
        head = "$ANSIBLE_VAULT;1.1"
        enc = Nanvault::Encrypted.new [head, body_ok]
        expect_raises(Nanvault::BadFile, "Invalid input file: bad header") do
          enc.parse
        end
      end

      it "correctly handles unsupported header" do
        head = "FOOFILEHEAD"
        enc = Nanvault::Encrypted.new [head, body_ok]
        expect_raises(Nanvault::BadFile, "Invalid input file: bad header") do
          enc.parse
        end
      end

      it "correctly handles unsupported version" do
        head = "$ANSIBLE_VAULT;1.0;AES"
        enc = Nanvault::Encrypted.new [head, body_ok]
        expect_raises(Nanvault::BadFile, "Sorry: file format version 1.0 is not supported") do
          enc.parse
        end
      end

      it "correctly parse ok hex body" do
        enc = Nanvault::Encrypted.new [header_ok, body_ok]
        enc.parse
        enc.bbody.should eq body_ok_bytes
      end

      it "correctly handles non-hex body" do
        enc = Nanvault::Encrypted.new [header_ok, "11ZZ11"]
        expect_raises(Nanvault::BadFile, "Invalid input file body") do
          enc.parse
        end
      end

    end
  end

end

require "./spec_helper"

describe Nanvault do
  # Nanvault tests

  describe Nanvault::Encrypted do

    header_ok = "$ANSIBLE_VAULT;1.1;AES256"

    body_ok = "34393465386232383131386237626532306236396636396135393664323834383838313035666331" \
              "6564353662313632616133366237393830393036303833320a356631363739393737316664313765" \
              "63336362376661303365386566363361306630323639326161313166613564363561306133643662" \
              "6466666165383365640a646365656164633362346630396335396365313231303238643039303937" \
              "64393735663933666330366466393366376164306531313238393334633266646165"

    body_ok_bytes = [52, 57, 52, 101, 56, 98, 50, 56, 49, 49, 56, 98, 55, 98, 101, 50, 48, 98, 54,
                      57, 102, 54, 57, 97, 53, 57, 54, 100, 50, 56, 52, 56, 56, 56, 49, 48, 53,
                      102, 99, 49, 101, 100, 53, 54, 98, 49, 54, 50, 97, 97, 51, 54, 98, 55, 57,
                      56, 48, 57, 48, 54, 48, 56, 51, 50, 10, 53, 102, 49, 54, 55, 57, 57, 55, 55,
                      49, 102, 100, 49, 55, 101, 99, 51, 99, 98, 55, 102, 97, 48, 51, 101, 56,
                      101, 102, 54, 51, 97, 48, 102, 48, 50, 54, 57, 50, 97, 97, 49, 49, 102, 97,
                      53, 100, 54, 53, 97, 48, 97, 51, 100, 54, 98, 100, 102, 102, 97, 101, 56, 51,
                      101, 100, 10, 100, 99, 101, 101, 97, 100, 99, 51, 98, 52, 102, 48, 57, 99,
                      53, 57, 99, 101, 49, 50, 49, 48, 50, 56, 100, 48, 57, 48, 57, 55, 100, 57,
                      55, 53, 102, 57, 51, 102, 99, 48, 54, 100, 102, 57, 51, 102, 55, 97, 100, 48,
                      101, 49, 49, 50, 56, 57, 51, 52, 99, 50, 102, 100, 97, 101]

    body_ok_salt = [52, 57, 52, 101, 56, 98, 50, 56, 49, 49, 56, 98, 55, 98, 101, 50, 48, 98, 54,
                    57, 102, 54, 57, 97, 53, 57, 54, 100, 50, 56, 52, 56, 56, 56, 49, 48, 53,
                    102, 99, 49, 101, 100, 53, 54, 98, 49, 54, 50, 97, 97, 51, 54, 98, 55, 57,
                    56, 48, 57, 48, 54, 48, 56, 51, 50]

    body_ok_hmac = [53, 102, 49, 54, 55, 57, 57, 55, 55,
                    49, 102, 100, 49, 55, 101, 99, 51, 99, 98, 55, 102, 97, 48, 51, 101, 56,
                    101, 102, 54, 51, 97, 48, 102, 48, 50, 54, 57, 50, 97, 97, 49, 49, 102, 97,
                    53, 100, 54, 53, 97, 48, 97, 51, 100, 54, 98, 100, 102, 102, 97, 101, 56, 51,
                    101, 100]
    
    body_ok_ctext = [100, 99, 101, 101, 97, 100, 99, 51, 98, 52, 102, 48, 57, 99,
                    53, 57, 99, 101, 49, 50, 49, 48, 50, 56, 100, 48, 57, 48, 57, 55, 100, 57,
                    55, 53, 102, 57, 51, 102, 99, 48, 54, 100, 102, 57, 51, 102, 55, 97, 100, 48,
                    101, 49, 49, 50, 56, 57, 51, 52, 99, 50, 102, 100, 97, 101]

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
        expect_raises(Nanvault::BadFile, "Invalid encoding in input file body") do
          enc.parse
        end
      end

      it "correctly parse ok body" do
        enc = Nanvault::Encrypted.new [header_ok, body_ok]
        enc.parse
        enc.bbody.should eq body_ok_bytes
        enc.salt.should eq body_ok_salt
        enc.hmac.should eq body_ok_hmac
        enc.ctext.should eq body_ok_ctext
      end

      it "correctly handles short body - no ctext" do
        enc = Nanvault::Encrypted.new [header_ok, "110a11"]
        expect_raises(Nanvault::BadFile, "Invalid input file body") do
          enc.parse
        end
      end

      it "correctly handles short body - no hmac" do
        enc = Nanvault::Encrypted.new [header_ok, "11"]
        expect_raises(Nanvault::BadFile, "Invalid input file body") do
          enc.parse
        end
      end

      it "correctly handles short body - empty salt" do
        enc = Nanvault::Encrypted.new [header_ok, ""]
        expect_raises(Nanvault::BadFile, "Invalid input file body") do
          enc.parse
        end
      end

      it "correctly handles short body - empty hmac" do
        enc = Nanvault::Encrypted.new [header_ok, "110a0a"]
        expect_raises(Nanvault::BadFile, "Invalid input file body") do
          enc.parse
        end
      end

      it "correctly handles short body - all empty" do
        enc = Nanvault::Encrypted.new [header_ok, "0a0a"]
        expect_raises(Nanvault::BadFile, "Invalid input file body") do
          enc.parse
        end
      end

    end
  end

  describe Nanvault::Crypto do

    salt = [52_u8, 57_u8, 52_u8, 101_u8, 56_u8, 98_u8, 50_u8, 56_u8, 49_u8,
            49_u8, 56_u8, 98_u8, 55_u8, 98_u8, 101_u8, 50_u8, 48_u8, 98_u8, 54_u8,
            57_u8, 102_u8, 54_u8, 57_u8, 97_u8, 53_u8, 57_u8, 54_u8, 100_u8, 50_u8,
            56_u8, 52_u8, 56_u8, 56_u8, 56_u8, 49_u8, 48_u8, 53_u8,
            102_u8, 99_u8, 49_u8, 101_u8, 100_u8, 53_u8, 54_u8, 98_u8, 49_u8,
            54_u8, 50_u8, 97_u8, 97_u8, 51_u8, 54_u8, 98_u8, 55_u8, 57_u8,
            56_u8, 48_u8, 57_u8, 48_u8, 54_u8, 48_u8, 56_u8, 51_u8, 50_u8]

    password = "foo"

    exp_cipher_key = [78, 116, 215, 252, 194, 36, 178, 70, 82, 251, 119, 224, 218,
                      116, 83, 153, 69, 169, 197, 227, 207, 51, 20, 39, 194, 230,
                      183, 145, 74, 110, 205, 39]
    
    exp_hmac_key = [238, 131, 245, 97, 171, 142, 161, 134, 156, 85, 239, 81, 162,
                    17, 4, 52, 214, 103, 81, 58, 45, 156, 186, 98, 140, 179, 91,
                    35, 115, 63, 43, 66]

    exp_cipher_iv = [57, 38, 0, 68, 121, 201, 134, 53, 117, 66, 217, 173, 180, 21, 117, 76]

    describe "#get_keys_iv" do
      it "correctly get keys and iv" do
        cipher_key, hmac_key, cipher_iv = Nanvault::Crypto.get_keys_iv(salt, password)
        cipher_key.should eq exp_cipher_key
        hmac_key.should eq exp_hmac_key
        cipher_iv.should eq exp_cipher_iv
      end
    end

  end

end

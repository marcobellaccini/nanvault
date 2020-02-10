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

    body_no_ctext = "34393465386232383131386237626532306236396636396135393664323834383838313035666331" \
              "6564353662313632616133366237393830393036303833320a356631363739393737316664313765" \
              "63336362376661303365386566363361306630323639326161313166613564363561306133643662" \
              "6466666165383365640a"

    body_no_hmac = "34393465386232383131386237626532306236396636396135393664323834383838313035666331" \
              "6564353662313632616133366237393830393036303833320a"

    body_ok_bytes = Bytes[52, 57, 52, 101, 56, 98, 50, 56, 49, 49, 56, 98, 55, 98, 101, 50, 48, 98, 54,
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

    body_ok_salt = Bytes[73, 78, 139, 40, 17, 139, 123, 226, 11, 105, 246, 154, 89, 109, 40, 72,
                         136, 16, 95, 193, 237, 86, 177, 98, 170, 54, 183, 152, 9, 6, 8, 50]

    body_ok_hmac = Bytes[95, 22, 121, 151, 113, 253, 23, 236, 60, 183, 250, 3, 232, 239, 99, 160,
                          240, 38, 146, 170, 17, 250, 93, 101, 160, 163, 214, 189, 255, 174, 131, 237]
    
    body_ok_ctext = Bytes[220, 238, 173, 195, 180, 240, 156, 89, 206, 18, 16, 40, 208, 144, 151, 217,
                          117, 249, 63, 192, 109, 249, 63, 122, 208, 225, 18, 137, 52, 194, 253, 174]

    password = "foo"

    ptext = Bytes[45, 45, 45, 10, 35, 32, 84, 101, 115, 116, 32, 102, 105, 108, 101, 10, 45,
                      32, 79, 110, 101, 10, 45, 32, 84, 119, 111, 10]

    describe "#initialize" do
      it "correctly loads header and body" do
        enc = Nanvault::Encrypted.new ["HEADER", "BODY1", "BODY2"]
        enc.header.should eq("HEADER")
        enc.body.should eq("BODY1BODY2")
      end

      it "correctly handles empty array" do
        expect_raises(Nanvault::BadData, "Invalid input file") do
          enc = Nanvault::Encrypted.new Array(String).new
        end
      end

      it "correctly handles header-only file" do
        expect_raises(Nanvault::BadData, "Invalid input file") do
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
        expect_raises(Nanvault::BadData, "Invalid input file: bad header") do
          enc.parse
        end
      end

      it "correctly handles unsupported header" do
        head = "FOOFILEHEAD"
        enc = Nanvault::Encrypted.new [head, body_ok]
        expect_raises(Nanvault::BadData, "Invalid input file: bad header") do
          enc.parse
        end
      end

      it "correctly handles unsupported version" do
        head = "$ANSIBLE_VAULT;1.0;AES"
        enc = Nanvault::Encrypted.new [head, body_ok]
        expect_raises(Nanvault::BadData, "Sorry: file format version 1.0 is not supported") do
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
        expect_raises(Nanvault::BadData, "Invalid encoding in input file body") do
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
        enc = Nanvault::Encrypted.new [header_ok, body_no_ctext]
        expect_raises(Nanvault::BadData, "Invalid input file body") do
          enc.parse
        end
      end

      it "correctly handles short body - no hmac" do
        enc = Nanvault::Encrypted.new [header_ok, body_no_hmac]
        expect_raises(Nanvault::BadData, "Invalid input file body") do
          enc.parse
        end
      end

      it "correctly handles short body - empty salt" do
        enc = Nanvault::Encrypted.new [header_ok, ""]
        expect_raises(Nanvault::BadData, "Invalid input file body") do
          enc.parse
        end
      end

      it "correctly handles short body - all empty" do
        enc = Nanvault::Encrypted.new [header_ok, ""]
        expect_raises(Nanvault::BadData, "Invalid input file body") do
          enc.parse
        end
      end

      it "correctly decrypts data - ok" do
        enc = Nanvault::Encrypted.new [header_ok, body_ok]
        enc.parse
        enc.password = password
        enc.decrypt
        enc.ptext.should eq ptext
      end

      it "correctly decrypts data - bad password" do
        enc = Nanvault::Encrypted.new [header_ok, body_ok]
        enc.parse
        enc.password = "badpassword"
        expect_raises(Nanvault::BadData, "Bad HMAC: wrong password or corrupted data") do
          enc.decrypt
        end
      end

    end
  end

  describe Nanvault::Crypto do

    salt_hex = Bytes[52, 57, 52, 101, 56, 98, 50, 56, 49,
            49, 56, 98, 55, 98, 101, 50, 48, 98, 54,
            57, 102, 54, 57, 97, 53, 57, 54, 100, 50,
            56, 52, 56, 56, 56, 49, 48, 53,
            102, 99, 49, 101, 100, 53, 54, 98, 49,
            54, 50, 97, 97, 51, 54, 98, 55, 57,
            56, 48, 57, 48, 54, 48, 56, 51, 50]

    
    salt_hex_arr = salt_hex.to_a

    salt_hex_arr_chr = salt_hex_arr.map { |x| x.as(UInt8).chr }

    salt = salt_hex_arr_chr.join.hexbytes

    password = "foo"

    passbytes = password.to_slice

    cipher_key = Bytes[242, 148, 14, 232, 107, 148, 161, 161, 231, 163, 33, 126, 76, 248,
                           111, 156, 80, 25, 167, 128, 63, 196, 218, 59, 57, 127, 201, 253,
                           181, 244, 183, 59]
    
    hmac_key = Bytes[87, 24, 4, 143, 42, 152, 187, 104, 86, 91, 63, 212, 89, 61, 132, 54,
                         14, 218, 203, 106, 210, 14, 14, 151, 1, 125, 248, 53, 191, 53, 199, 108]

    cipher_iv = Bytes[251, 188, 216, 52, 195, 36, 99, 37, 67, 211, 168, 145, 210, 132, 3, 235]

    hmac = Bytes[95, 22, 121, 151, 113, 253, 23, 236, 60, 183, 250, 3, 232, 239, 99, 160,
                          240, 38, 146, 170, 17, 250, 93, 101, 160, 163, 214, 189, 255, 174, 131, 237]

    hmac_bad = Bytes[96, 23, 121, 151, 113, 253, 23, 236, 60, 183, 250, 3, 232, 239, 99, 160,
                          240, 38, 146, 170, 17, 250, 93, 101, 160, 163, 214, 189, 255, 174, 131, 237]

    ptext = Bytes[45, 45, 45, 10, 35, 32, 84, 101, 115, 116, 32, 102, 105, 108, 101, 10, 45,
                      32, 79, 110, 101, 10, 45, 32, 84, 119, 111, 10]

    ctext = Bytes[220, 238, 173, 195, 180, 240, 156, 89, 206, 18, 16, 40, 208, 144, 151, 217,
                  117, 249, 63, 192, 109, 249, 63, 122, 208, 225, 18, 137, 52, 194, 253, 174]

    describe "#get_keys_iv" do
      it "correctly get keys and iv" do
        com_cipher_key, com_hmac_key, com_cipher_iv = Nanvault::Crypto.get_keys_iv(salt, passbytes)
        com_cipher_key.should eq cipher_key
        com_hmac_key.should eq hmac_key
        com_cipher_iv.should eq cipher_iv
      end
    end

    describe "#check_hmac" do
      it "correctly checks valid hmac" do
        Nanvault::Crypto.check_hmac(ctext, hmac_key, hmac).should eq true
      end
      it "correctly handles invalid hmac" do
        expect_raises(Nanvault::BadData, "Bad HMAC: wrong password or corrupted data") do
          Nanvault::Crypto.check_hmac(ctext, hmac_key, hmac_bad)
        end
      end
    end

    describe "#decrypt" do
      it "correctly decrypt data" do
        com_ptext = Nanvault::Crypto.decrypt(cipher_iv, cipher_key, ctext)
        com_ptext.should eq ptext
      end
    end

  end

  describe Nanvault::VarUtil do
    hex = Bytes[52, 57, 52, 101, 56, 98, 50, 56, 49,
            49, 56, 98, 55, 98, 101, 50, 48, 98, 54,
            57, 102, 54, 57, 97, 53, 57, 54, 100, 50,
            56, 52, 56, 56, 56, 49, 48, 53,
            102, 99, 49, 101, 100, 53, 54, 98, 49,
            54, 50, 97, 97, 51, 54, 98, 55, 57,
            56, 48, 57, 48, 54, 48, 56, 51, 50]

    plain_bytes = Bytes[73, 78, 139, 40, 17, 139, 123, 226, 11, 105, 246, 154, 89, 109, 40, 72,
                      136, 16, 95, 193, 237, 86, 177, 98, 170, 54, 183, 152, 9, 6, 8, 50]
    
    describe "#unhexlify" do
      it "correctly unhexlifies data" do
        Nanvault::VarUtil.unhexlify(hex).should eq plain_bytes
      end
      it "correctly handles invalid hex data" do
        expect_raises(Nanvault::BadData, "Bad data: invalid hex") do
          Nanvault::VarUtil.unhexlify(Bytes[52,252])
        end
      end
    end

  end

end

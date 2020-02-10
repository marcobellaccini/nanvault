require "openssl"
require "openssl/hmac"

# TODO: Write documentation for `Nanvault`
module Nanvault
  VERSION = "0.1.0"

  # Encrypted file class
  class Encrypted
    # these initializations also prevent this:
    # https://github.com/crystal-lang/crystal/issues/5931
    property header = "", body = "", password = ""
    property bbody = Slice(UInt8).new 1
    property salt = Slice(UInt8).new 1
    property hmac = Slice(UInt8).new 1
    property ctext = Slice(UInt8).new 1
    property ptext = Slice(UInt8).new 1
    property vault_info = Hash(String, String | Nil).new

    def initialize(ctext_lines : Array(String))
      @header = ctext_lines[0]
      # this also handles the header-only file case
      if ctext_lines[1]
        @body = ctext_lines[1..-1].join()
      end

      # rescue for bad files
      rescue ex: IndexError
        raise BadData.new("Invalid input file")
    end

    # parse method
    def parse()
      parse_header()

      case @vault_info["version"]
      when "1.1","1.2"
        parse_body()
      else
        raise BadData.new("Sorry: file format version #{@vault_info["version"]} is not supported")
      end

    end

    # parse header method
    private def parse_header()
      header_re = /^\$ANSIBLE_VAULT;(?<version>[^;\n\s]+);(?<alg>[^;\n\s]+);?(?<label>[^;\n\s]+)?$/
      match = header_re.match(@header)

      if ! match
        raise BadData.new("Invalid input file: bad header")
      end
      
      @vault_info = match.named_captures

    end

    # parse body method
    private def parse_body()
      get_bytes()

      salt_end_idx = @bbody.index { |x| x == 0x0a_u8}

      if ! salt_end_idx
        raise BadData.new("Invalid input file body")
      end

      # unhexlify again (revert nested hexlify)
      salt_hex_bytes = @bbody[0..(salt_end_idx - 1)]
      @salt = VarUtil.unhexlify(salt_hex_bytes)

      rem_bbody = @bbody + salt_hex_bytes.size + 1

      hmac_end_idx = rem_bbody.index { |x| x == 0x0a_u8 }

      if ! hmac_end_idx
        raise BadData.new("Invalid input file body")
      end

      # unhexlify again (revert nested hexlify)
      hmac_hex_bytes = rem_bbody[0..(hmac_end_idx - 1)]
      @hmac = VarUtil.unhexlify(hmac_hex_bytes)

      # unhexlify again (revert nested hexlify)
      ctext_hex_bytes = rem_bbody + hmac_hex_bytes.size + 1
      @ctext = VarUtil.unhexlify(ctext_hex_bytes)

      if @salt.size == 0 || @hmac.size == 0 || @ctext.size == 0
        raise BadData.new("Invalid input file body")
      end

    rescue ex: IndexError
      raise BadData.new("Invalid input file body")
    rescue ex: ArgumentError
      raise BadData.new("Invalid input file body")

    end

    # decrypt method
    def decrypt()
      cipher_key, hmac_key, cipher_iv = Crypto.get_keys_iv(@salt, @password.to_slice)
      Crypto.check_hmac(@ctext, hmac_key, @hmac)
      @ptext = Crypto.decrypt(cipher_iv, cipher_key, @ctext)
    end

    # get bytes method
    # this performs an implicit "unhexlify-equivalent"
    private def get_bytes()
      @bbody = @body.hexbytes
      rescue ex: ArgumentError
        raise BadData.new("Invalid encoding in input file body")
    end

  end

  # Crypto class
  class Crypto
    PBKDF2_ITERATIONS = 10000
    PBKDF2_ALG = OpenSSL::Algorithm::SHA256
    HMAC_ALG = OpenSSL::Algorithm::SHA256
    PBKDF2_KEY_SIZE = 80
    CIPHER_ALG_DEFAULT = "aes-256-ctr"

    # class method to get cipher key, HMAC key and cipher IV
    def self.get_keys_iv(salt, password)
      key = OpenSSL::PKCS5.pbkdf2_hmac(password, salt, PBKDF2_ITERATIONS, PBKDF2_ALG, PBKDF2_KEY_SIZE)
      cipher_key = key[0..31]
      hmac_key = key[32..63]
      cipher_iv = key[64..-1]
      return {cipher_key, hmac_key, cipher_iv}
    end

    # class method to check HMAC
    def self.check_hmac(data, key, exp_hmac)
      hmac = OpenSSL::HMAC.digest(HMAC_ALG, key, data)
      if hmac != exp_hmac
        raise BadData.new("Bad HMAC: wrong password or corrupted data")
      end
      return true
    end

    # class method to decrypt ciphertext
    def self.decrypt(cipher_iv, cipher_key, ciphertext, algorithm = CIPHER_ALG_DEFAULT)
      cipher = OpenSSL::Cipher.new(algorithm)
      cipher.decrypt
      cipher.iv = cipher_iv
      cipher.key = cipher_key
      ptext_start = cipher.update(ciphertext)
      ptext_end = cipher.final

      # concatenate slices
      ret_slice = Slice(UInt8).new(ptext_start.size + ptext_end.size)
      ptext_start.copy_to ret_slice
      ptext_end.copy_to(ret_slice + ptext_start.size)

      # remove padding
      padbytes = ret_slice[-1]
      ret_slice = ret_slice[0..-1-padbytes]

      return ret_slice
    end

  end

  # VarUtil Class
  class VarUtil
    # class method to perform unhexlify
    # https://docs.python.org/3.8/library/binascii.html#binascii.unhexlify
    def self.unhexlify(hinsl)
      hinsl_arr = hinsl.to_a
      hinsl_arr_chr = hinsl_arr.map { |x| x.as(UInt8).chr }
      return hinsl_arr_chr.join.hexbytes

      rescue ArgumentError
        raise BadData.new("Bad data: invalid hex")
    end
  end

  # Exception type for bad files
  class BadData < Exception
  end
end

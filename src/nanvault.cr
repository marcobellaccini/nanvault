# TODO: Write documentation for `Nanvault`
module Nanvault
  VERSION = "0.1.0"

  # TODO: Write documentation
  class Encrypted
    # these initializations also prevent this:
    # https://github.com/crystal-lang/crystal/issues/5931
    property header = "", body = ""
    property bbody = Array(UInt8).new
    property salt = Array(UInt8).new
    property hmac = Array(UInt8).new
    property ctext = Array(UInt8).new
    property vault_info = Hash(String, String | Nil).new

    def initialize(ctext_lines : Array(String))
      @header = ctext_lines[0]
      # this also handles the header-only file case
      if ctext_lines[1]
        @body = ctext_lines[1..-1].join()
      end

      # rescue for bad files
      rescue ex: IndexError
        raise BadFile.new("Invalid input file")
    end

    # parse method
    def parse()
      parse_header()

      case @vault_info["version"]
      when "1.1","1.2"
        parse_body()
      else
        raise BadFile.new("Sorry: file format version #{@vault_info["version"]} is not supported")
      end

    end

    # parse header method
    private def parse_header()
      header_re = /^\$ANSIBLE_VAULT;(?<version>[^;\n\s]+);(?<alg>[^;\n\s]+);?(?<label>[^;\n\s]+)?$/
      match = header_re.match(@header)

      if ! match
        raise BadFile.new("Invalid input file: bad header")
      end
      
      @vault_info = match.named_captures

    end

    # parse body method
    private def parse_body()
      get_bytes()

      @salt = (@bbody.take_while { |x| x != 0x0a_u8})

      rem_bbody = @bbody[@salt.size+1..-1]

      @hmac = (rem_bbody.take_while { |x| x != 0x0a_u8})

      @ctext = rem_bbody[@hmac.size+1..-1]

      if @salt.size == 0 || @hmac.size == 0 || @ctext.size == 0
        raise BadFile.new("Invalid input file body")
      end

    rescue ex: IndexError
      raise BadFile.new("Invalid input file body")

    end

    # get bytes method
    private def get_bytes()
      @bbody = @body.hexbytes.to_a
      rescue ex: ArgumentError
        raise BadFile.new("Invalid encoding in input file body")
    end

  end

  # Exception type for bad files
  class BadFile < Exception
  end
end

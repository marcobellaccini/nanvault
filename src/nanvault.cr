# TODO: Write documentation for `Nanvault`
module Nanvault
  VERSION = "0.1.0"

  # TODO: Write documentation
  class Encrypted
    # these initializations also prevent this:
    # https://github.com/crystal-lang/crystal/issues/5931
    property header = "", body = ""

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

  end

  # Exception type for bad files
  class BadFile < Exception
  end
end

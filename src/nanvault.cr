# TODO: Write documentation for `Nanvault`
module Nanvault
  VERSION = "0.1.0"

  # TODO: Put your code here

  # TODO: Write documentation
  class Encrypted
    property header : String, body : String

    def initialize(@ctext_lines : Array(String))
      @header = ctext_lines[0]
      @body = ctext_lines[1..-1].join()
    end
  end
end

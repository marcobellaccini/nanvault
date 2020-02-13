require "option_parser"
require "./nanvault"

# environment variable key for vault password file
ENV_NAME = "NANVAULT_PASSFILE"

# password file short option
PASSFILE_SHORT_OPT = "-p PASSFILE"

label = ""
op = :none
password = ""
infile = ""
outfile = ""
pass_file_passed = ""
pass_file = ""

OptionParser.parse do |parser|
  parser.banner = "Usage: nanvault"
  parser.on(PASSFILE_SHORT_OPT, "--vault-password-file=PASSFILE", "Specifies the vault password file") { |p| pass_file_passed = p }
  parser.on("-g", "--generate", "Generate safe password") { puts "#{Nanvault::Crypto.genpass}"; exit(0) }
  parser.on("-l LABEL", "--label=LABEL", "Specifies the vault-id-label") { |l| label = l }
  parser.on("-h", "--help", "Show this help") { puts parser; exit(0) }
  parser.unknown_args do |args|
    if args.size != 0
      STDERR.puts "ERROR: this program does not need arguments!"
      STDERR.puts parser
      exit(1)
    end
  end
  parser.invalid_option do |flag|
    STDERR.puts "ERROR: #{flag} is not a valid option."
    STDERR.puts parser
    exit(1)
  end
end

# if a password file was specified via command-line option
if pass_file_passed != ""
    pass_file = pass_file_passed
# if a password file was not specified
# but the ENV_NAME env var is available
elsif ENV.has_key?(ENV_NAME)
    pass_file = ENV[ENV_NAME]
else
    STDERR.puts "ERROR: no password file is available."
    STDERR.puts "Please specify a password file through the '#{PASSFILE_SHORT_OPT}' " \
                "command-line option or the '#{ENV_NAME}' environment variable."
    exit(1)
end

# read password file
if pass_file != ""
  begin
    password = File.read(pass_file)
  rescue
    STDERR.puts "ERROR: unable to read vault password file '#{pass_file}'"
    exit(1)
  end
end

# read input from stdin
begin
  in_data = STDIN.gets_to_end
rescue
  STDERR.puts "ERROR: unable to get input data."
  exit(1)
end

# determine whether to encrypt or decrypt
# (by checking if input data is already encrypted)
if in_data.starts_with?("$ANSIBLE_VAULT")
  op = :decrypt
else
  op = :encrypt
end

begin
  case op
  when :encrypt
    pt = Nanvault::Plaintext.new in_data
    pt.password = password || ""
    if label != ""
      pt.label = label
    end
    pt.encrypt
    out_data = pt.encrypted_str
  when :decrypt
    enc = Nanvault::Encrypted.new in_data
    enc.password = password || ""
    enc.decrypt
    out_data = enc.plaintext_str
  end
rescue ex
  puts "ERROR: #{ex.message}"
else
  # write output to stdout, without trailing newline
  STDOUT.print "#{out_data}"
  STDOUT.flush
end

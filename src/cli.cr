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
  parser.banner = "nanvault: a standalone CLI tool to encrypt and decrypt files in the Ansible Vault format.\n" \
                  "More information, usage examples and candies at:\n" \
                  "https://github.com/marcobellaccini/nanvault\n" \
                  "Usage: nanvault"
  parser.on(PASSFILE_SHORT_OPT, "--vault-password-file=PASSFILE", "Specifies the vault password file") { |p| pass_file_passed = p }
  parser.on("-g", "--generate", "Password-generation mode: generates safe password") { write_stdout(Nanvault::Crypto.genpass); exit(0) }
  parser.on("-y KEYNAME", "--to-yaml=KEYNAME", "YAML-string mode: to YAML") { |k| to_yaml_mode(k) }
  parser.on("-Y", "--from-yaml", "YAML-string mode: from YAML") { from_yaml_mode() }
  parser.on("-l LABEL", "--label=LABEL", "Specifies the vault-id-label") { |l| label = l }
  parser.on("--version", "Print version") { puts "nanvault version #{Nanvault::VERSION}"; exit(0) }
  parser.on("-h", "--help", "Show this help") { puts parser; exit(0) }
  parser.unknown_args do |args|
    # filter out unknown options
    unk_args = args.find { |s| !s.starts_with?("-") }
    if !unk_args.nil?
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
  parser.missing_option do |flag|
    STDERR.puts "ERROR: incomplete or missing option '#{flag}'."
    STDERR.puts parser
    exit(1)
  end
end

# method to handle to-yaml mode
def to_yaml_mode(yaml_key)
  in_data = read_stdin()
  begin
    out_data = Nanvault::YAMLString.get_yaml(yaml_key, in_data)
  rescue ex
    STDERR.puts "ERROR: #{ex.message}"
    exit(1)
  end
  write_stdout(out_data)
  exit(0)
end

# method to handle from-yaml mode
def from_yaml_mode
  in_data = read_stdin()
  begin
    out_data = Nanvault::YAMLString.get_value(in_data)
  rescue ex
    STDERR.puts "ERROR: #{ex.message}"
    exit(1)
  end
  write_stdout(out_data)
  exit(0)
end

# method to read from stdin
def read_stdin
  # read input from stdin
  begin
    return STDIN.gets_to_end
  rescue
    STDERR.puts "ERROR: unable to get input data."
    exit(1)
  end
end

# method to write to stdout
def write_stdout(data)
  # write to stdout without trailing newline
  STDOUT.print "#{data}"
  STDOUT.flush
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
    # in order to mimic ansible-vault behavior, newline should be chomped
    password = File.read(pass_file).chomp
  rescue
    STDERR.puts "ERROR: unable to read vault password file '#{pass_file}'"
    exit(1)
  end
end

# read input from stdin
in_data = read_stdin()

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
  STDERR.puts "ERROR: #{ex.message}"
  exit(1)
else
  # write output to stdout
  write_stdout(out_data)
  exit(0)
end

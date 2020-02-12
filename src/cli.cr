require "option_parser"
require "./nanvault"

label = ""
op = :none
password = ""
infile = ""
outfile = ""
pass_file = ""

OptionParser.parse do |parser|
  parser.banner = "Usage: nanvault"
  parser.on("-l LABEL", "--label=LABEL", "Specifies the vault-id-label") { |l| label = l }
  parser.on("-p FILE", "--vault-password-file=FILE", "Specifies the vault password file") { |p| pass_file = p }
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

# if a password file was specified
if pass_file != ""
  begin
    password = File.read(pass_file)
  rescue
    STDERR.puts "ERROR: unable to read vault password file."
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

# if no password file was specified
if pass_file == ""
  # get password
  puts "Enter password:"
  password = STDIN.noecho &.gets.try &.chomp
end

if password == Nil || password == ""
  STDERR.puts "ERROR: invalid password."
  exit(1)
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

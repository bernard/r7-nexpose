#!/usr/bin/env ruby

# Rapid7 Nexpose Bulk Site Creation
# A CSV file is needed for this to work.

# Bernard Bolduc


require 'nexpose'
require 'io/console'
require 'csv'
require 'optparse'
require 'time'

options = {:import => false, :list => false, :action => false, :user => nil, :host => nil, :port => '443', :file => nil}
parser = OptionParser.new do |opts|
	opts.banner = "Nexpose Bulk Site Creator\nUsage: nexpose-bulk.rb [options]\nOne action is mandatory"
  opts.on('-i', '--import', 'Action: Bulk Import') do |import|
		options[:import] = true;
		options[:action] = true;
  end

  opts.on('-l', '--list', 'Action: List Sites') do |list|
		options[:list] = true;
		options[:action] = true;
  end

	opts.on('-u', '--usernane name', 'Username') do |user|
		options[:user] = user;
	end

	opts.on('-s', '--server host', 'Nexpose Host') do |host|
		options[:host] = host;
	end

	opts.on('-p', '--port port', 'Nexpose Port default: 443') do |port|
		options[:port] = port;
	end

	opts.on('-f', '--file filename', 'CSV File') do |file|
		options[:file] = file;
	end

	opts.on('-t', '--template', 'Display CSV File Template') do |template|
		puts 'Use this header in your CSV file'
		puts ''
		puts 'name,description,ip_address,template_id,schedule,alerts_id,date_time'
		exit
	end

	opts.on('-h', '--help', 'Displays Help') do
		puts opts
		exit
	end
end

parser.parse!

if options[:action] == false
  puts "Missing action!"
  puts " --help for help"
  exit 1
end

if options[:user] == nil
  puts "Missing user!"
  puts "--help for help"
  exit 1
end

@host = options[:host]
@port = options[:port]
@user = options[:user]
@file = options[:file]

# this function creates the password prompt,
# which uses io/console functionality to hide the password while typing
def get_password(prompt="Nexpose password to #{@user}: ")
  print prompt
  STDIN.noecho(&:gets).chomp
end

# we set the password variable by using the above function to get user input
@password = get_password

# Create a new Nexpose::Connection on the default port
puts "\nConnecting to #{@host}:#{@port} as #{@user}..."
@nsc = Nexpose::Connection.new(@host, @user, @password, @port)

# Login to NSC and Establish a Session ID
@nsc.login

# Check Session ID
if @nsc.session_id
    puts 'Login Successful'
else
    puts 'Login Failure'
end

# List function
def list_sites
  puts "Listing Sites..."

  # Get list of sites
  sites = @nsc.list_sites

  begin
    # we're going to step through each site in the site listing
    sites.each do |site|
      begin
        site = Nexpose::Site.load(@nsc, site.id)
        puts "------------------------------------------------------------------------------"
        puts "Loaded Site ID #{site.id}"
        puts "Site Name #{site.name}."
        puts "Description #{site.description}."
        puts "Scan Template ID - #{site.scan_template_id}."
        puts "Scan Template Name - #{site.scan_template_name}."
        site.alerts.each do |alert|
          puts "Alert #{alert.name} is #{alert.enabled ? "Enabled" : "Disabled"} with #{alert.max_alerts} max alerts"
          puts "Scan Filters enabled are: "
          puts "   start" if alert.scan_filter.start
          puts "   stop" if alert.scan_filter.stop
          puts "   fail" if alert.scan_filter.fail
          puts "   resume" if alert.scan_filter.resume
          puts "   pause" if alert.scan_filter.pause
          puts "Vulnerability Filters enabled are: "
          puts "   severity" if alert.vuln_filter.severity
          puts "   confirmed" if alert.vuln_filter.confirmed
          puts "   unconfirmed" if alert.vuln_filter.unconfirmed
          puts "   potential" if alert.vuln_filter.potential

          if alert.instance_of? Nexpose::SMTPAlert
            puts "SMTP Alert with sender #{alert.sender} for server #{alert.server} with recipients #{alert.recipients}"
          elsif alert.instance_of? Nexpose::SNMPAlert
            puts "SNMP Alert with community #{alert.community} for server #{alert.server}"
          elsif alert.instance_of? Nexpose::SyslogAlert
            puts "Syslog Alert with server #{alert.server}"
          end
        end

      end

    end
  end

end

# Bulk Import function
def bulk_import
  puts 'Bulk Importing...'

  if @file == nil
    puts "Missing file argument!"
    puts "--help for help"
    exit 1
  end

  # CSV processing
  CSV.foreach(@file, :headers => true) do |row|
    #puts row.inspect
    @site_name = row['name']
    @site_description = row['description']
    @site_address = row['ip_address'].split(",")
    @site_scan_template_id = row['template_id']
    @site_scan_schedule = row['schedule']
    @site_clone_alerts_from = row['alerts_id']
    @site_scan_date_time = row['date_time']

    puts "Creating new site - #{@site_name}"
    site = Nexpose::Site.new(@site_name)
    site.description = @site_description
    @site_address.each do |address|
    site.include_asset(address)
    end
    site.scan_template_id = @site_scan_template_id
    case @site_scan_schedule
      when "daily"
        @my_schedule = Nexpose::Schedule.new(Nexpose::Schedule::Type::DAILY, 1, Time.parse(@site_scan_date_time).utc)
      when "hourly"
        @my_schedule = Nexpose::Schedule.new(Nexpose::Schedule::Type::HOURLY, 1, Time.parse(@site_scan_date_time).utc)
      when "weekly"
        @my_schedule = Nexpose::Schedule.new(Nexpose::Schedule::Type::WEEKLY, 1, Time.parse(@site_scan_date_time).utc)
      when "monthly-date"
        @my_schedule = Nexpose::Schedule.new(Nexpose::Schedule::Type::MONTHLY_DATE, 1, Time.parse(@site_scan_date_time).utc)
      when "monthly-day"
        @my_schedule = Nexpose::Schedule.new(Nexpose::Schedule::Type::MONTHLY_DAY, 1, Time.parse(@site_scan_date_time).utc)
    end
    site.schedules << @my_schedule

    # Cloning alerts
    alerts = Nexpose::Site.load(@nsc, @site_clone_alerts_from).alerts
    site.alerts = alerts

    site.save(@nsc)
  end

end

if options[:list] == true
  list_sites
end

if options[:import] == true
  bulk_import
end

# Logout
logout_success = @nsc.logout

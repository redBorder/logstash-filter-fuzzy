# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"

require 'json'

class LogStash::Filters::Ssdeep < LogStash::Filters::Base

  config_name "ssdeep"

  # Ssdeep binary path
  config :ssdeep_bin,      :validate => :string,    :default => "/usr/bin/ssdeep"
  # Ssdeep database path
  config :fuzzy_db,        :validate => :string,    :default => "/usr/share/logstash/fuzzy.db"
  # Similarity threshold
  config :threshold,       :validate => :number,    :default => 95
  # File that is going to be analyzed
  config :file_field,      :validate => :string,    :default => "[path]"
  # Loader weight
  config :weight,                                   :default => 1.0
  # Where you want the data to be placed
  config :target,           :validate => :string,   :default => "ssdeep"
  # Where you want the score to be placed
  config :score_name,       :validate => :string,   :default => "sb_ssdeep"
  # Where you want the latency to be placed
  config :latency_name,     :validate => :string,   :default => "ssdeep_latency"


  public
  def register
    # Add instance variables
  end # def register

  private

  def get_ssdeep_info
    ssdeep_info = {"Matches" => []}
    score = -1
    in_database = false

    unless File.exist?(@ssdeep_bin)
      @logger.error("Ssdeep binary is not in #{@ssdeep_bin}.")
      return [ssdeep_info,score]
    end

    unless File.exist?(@file_path)
      @logger.error("File #{@file_path} does not exist.")
      return [ssdeep_info,score]
    end

    unless File.exist?(@fuzzy_db)
      @logger.error("Database #{@fuzzy_db} does not exist.")
      return [ssdeep_info,score]
    end

    unless check_database
      @logger.error("Database #{@fuzzy_db} is not well formatted.")
      return [ssdeep_info,score]
    end

    _,_,_,@ssdeep,_ = `#{@ssdeep_bin} -s #{@file_path}`.split(/[,\n]/)

    results = `#{@ssdeep_bin} -t #{@threshold} -s -m #{@fuzzy_db} #{@file_path}`.split("\n")

    results.each do |result|
      _,hash_and_similarity = result.split(':')
      db_hash,similarity = hash_and_similarity.split(' ')
      if db_hash != @hash #Avoid duplicate events
        similarity = similarity.gsub(/[\(\)]/,'').to_i #Similarity comes in format '(similarity)'
        score = similarity if similarity > score
        ssdeep_info["Matches"].push({"hash" => db_hash, "similarity" => similarity})
      else
        in_database = true
      end
    end
    update_database unless in_database
    score = (score * @weight).round
    [ssdeep_info, score]
  end

  def update_database
    entry = @ssdeep + ',' + '"' +  @hash + '"'
    begin
      open(@fuzzy_db, 'a') do |f|
        f << entry + "\n"
      end
    rescue Errno::ENOENT => ex
      @logger.error(ex.message)
    end
  end

  # Check First line in Fuzzy database
  def check_database
    File.open(@fuzzy_db, &:readline) == "ssdeep,1.1--blocksize:hash:hash,filename\n"
  end


  public
  def filter(event)

    @file_path = event.get(@file_field)

    begin
      @hash = Digest::MD5.hexdigest File.read @file_path
    rescue Errno::ENOENT => ex
      @logger.error(ex.message)
    end

    starting_time = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    ssdeep_result,score = get_ssdeep_info

    ending_time  = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    elapsed_time = (ending_time - starting_time).round(1)

    event.set(@latency_name, elapsed_time)
    event.set(@target, ssdeep_result)
    event.set(@score_name, score)
    # filter_matched should go in the last line of our successful code
    filter_matched(event)

  end  # def filter(event)
end # class LogStash::Filters::Ssdeep

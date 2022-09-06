# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"

require 'json'
require 'aerospike'
require 'text'

require_relative "util/aerospike_config"
require_relative "util/aerospike_methods"

class LogStash::Filters::Fuzzy < LogStash::Filters::Base

  include Aerospike

  config_name "fuzzy"

  # Python path
  config :python,                           :validate => :string,           :default => "/usr/bin/python2.6"
  # Hasher python script path
  config :hasher_py,                        :validate => :string,           :default => "/opt/rb/var/rb-sequence-oozie/workflow/lib/scripts/hasher.py"
  # sdhash binary path
  config :sdhash_bin,                       :validate => :string,           :default => "/opt/rb/bin/sdhash"
  # Similarity threshold
  config :threshold,                        :validate => :number,           :default => 95
  # File that is going to be analyzed
  config :file_field,                       :validate => :string,           :default => "[path]"
  # Where you want the data to be placed
  config :target,                           :validate => :string,           :default => "fuzzy"
  # Where you want the score to be placed
  config :score_name,                       :validate => :string,           :default => "sb_fuzzy"
  # Where you want the latency to be placed
  config :latency_name,                     :validate => :string,           :default => "fuzzy_latency"
  #Aerospike server in the form "host:port"
  config :aerospike_server,                 :validate => :string,           :default => ""
  #Namespace is a Database name in Aerospike
  config :aerospike_namespace,              :validate => :string,           :default => "malware"
  #Set in Aerospike is similar to table in a relational database.
  # Where are fuzzy hashes stored
  config :aerospike_set_fuzzy_hash,         :validate => :string,           :default => "fuzzy"
  #Set in Aerospike is similar to table in a relational database.
  # Where are scores stored
  config :aerospike_set_scores,             :validate => :string,           :default => "hashScores"
  # Time to live values in fuzzy set
  config :ttl_fuzzy,                        :validate => :number,           :default => 0


  public
  def register
    # Add instance variables
    begin
      @aerospike_server = AerospikeConfig::servers if @aerospike_server.empty?
      @aerospike_server = @aerospike_server[0] if @aerospike_server.class.to_s == "Array"
      host,port = @aerospike_server.split(":")
      @aerospike = Client.new(Host.new(host, port))

    rescue Aerospike::Exceptions::Aerospike => ex
      @logger.error(ex.message)
    end
  end # def register

  private
  def get_fuzzy_hashes_from_file

    hashes = {"pe_hash" => '', "ssdeep" => '', "sdhash" => ''}

    unless File.exist?(@python)
      @logger.error("Python is not in #{@python}.")
      return [hashes["pe_hash"], hashes["ssdeep"], hashes["sdhash"]]
    end

    unless File.exist?(@hasher_py)
      @logger.error("Python hasher script is not in #{@hasher_py}.")
      return [hashes["pe_hash"], hashes["ssdeep"], hashes["sdhash"]]
    end

    begin
      hashes = JSON.parse(`#{@python} #{@hasher_py} #{@file_path}`)
    rescue JSON::ParserError
      @logger.error("Cannot get hashes from #{@file_path}")
    end

    [hashes["pe_hash"], hashes["ssdeep"], hashes["sdhash"].gsub(@file_path,@hash)]
  end

  def get_fuzzy_records
    AerospikeMethods::get_records(@aerospike,@aerospike_namespace,@aerospike_set_fuzzy_hash)
  end

  def get_pehash_info
    pehash_info = {"Matches" => []}

    if @pehash == ''
      return pehash_info
    end

    get_fuzzy_records.each do |record|
      key = record.key.user_key
      if @hash != key  #Avoid duplicate events
        record.bins.each do |column, value|
          if column == "pehash"
            pe_hash = value
            if pe_hash == @pehash
              pehash_info["Matches"].push({"hash" => key, "pehash" => pe_hash, "similarity" => 100})
            end
          end
        end
      end
    end
    pehash_info
  end

  def get_sdhash_info
    sdhash_info = {"Matches" => []}

    unless File.exist?(@sdhash_bin)
      @logger.error("Sdhash binary is not in #{@sdhash_bin}.")
      sdhash_info
    end

    if @sdhash == ''
      return sdhash_info
    end

    sdhashes = []
    get_fuzzy_records.each do |record|
      key = record.key.user_key
      if @hash != key  #Avoid duplicate events
        record.bins.each do |column, value|
          if column == "sdhash"
            sdhashes.push value
          end
        end
      end
    end
    unless sdhashes.empty?
      #Let's create databases
      dir = "/tmp/fuzzy/"
      Dir.mkdir dir unless Dir.exist? dir

      database1 = dir + "sdhash-file.sdbf"
      database2 = dir + "sdhash-file2.sdbf"

      open(database1, 'a') do |f|
        f << @sdhash + "\n"
      end

      open(database2, 'a') do |f|
        sdhashes.each do |hash|
          f << hash + "\n"
        end
      end

      coincidences = `#{@sdhash_bin} -c #{database1} #{database2} -t #{@threshold}`.split("\n")

      File.delete(database1)
      File.delete(database2)

      coincidences.each do |result|
        _,hash,similarity = result.split("|")
        sdhash_info["Matches"].push({"hash" => hash, "similarity" => similarity})
      end
    end
    sdhash_info
  end

  def get_ssdeep_info
    ssdeep_info = {"Matches" => []}


    if @ssdeep == ''
      return ssdeep_info
    end

    get_fuzzy_records.each do |record|
      key = record.key.user_key
      if @hash != key  #Avoid duplicate events
        record.bins.each do |column, value|
          if column == "ssdeep"
            ssdeep_hash = value
            similarity = compare_ssdeep(@ssdeep,ssdeep_hash)
            if similarity > @threshold
              ssdeep_info["Matches"].push({"hash" => key, "ssdeep" => ssdeep_hash ,"similarity" => similarity})
            end
          end
        end
      end
    end

    ssdeep_info
  end

  def compare_ssdeep(fh1,fh2)
    #fh fuzzy hash
    block_size1, str11, str12 = fh1.split(':')
    block_size2, str21, str22 = fh2.split(':')
    block_size1 = block_size1.to_i
    block_size2 = block_size2.to_i

    case block_size1
      when block_size2
        score1 = string_score(str11, str21, block_size1)
        score2 = string_score(str12, str22, block_size2)
        score = [score1, score2].min

      when block_size2 * 2
        score = string_score(str11, str22, block_size1).to_i.truncate

      when block_size2 / 2
        score = string_score(str12, str21, block_size2).to_i.truncate
      else
        score = 0
    end

    score
  end

  def string_score(str1,str2,block_size)
    spamsum_length = 64
    min_blocksize = 3

    len1 = str1.size
    len2 = str2.size

    return 0 if (len1 > spamsum_length || len2 > spamsum_length)

    lev_score = Text::Levenshtein.distance(str1, str2).to_f
    # Normalized Levenshtein Distance
    lev_score /= [len1,len2].max

    score = (1 - (lev_score / (len1 + len2))) * 100

    score_aux = block_size / min_blocksize * [len1,len2].min

    [score, score_aux].min
  end

  def add_hashes_to_aerospike

    begin
      bins = []

      bins.push(Bin.new("pehash", @pehash))
      bins.push(Bin.new("ssdeep", @ssdeep))
      bins.push(Bin.new("sdhash", @sdhash))

      AerospikeMethods::set_record(@aerospike, bins, @aerospike_namespace, @aerospike_set_fuzzy_hash, @hash, @ttl_fuzzy)
      #end
    rescue Aerospike::Exceptions::Aerospike => ex
      @logger.error(ex.message)
    end
  end

  def get_fuzzy_score(matches)
    score = 0

    #First we get a list of hashes with the maximum similarity
    hashes = []
    max_similarity = 0

    matches.each do |m|
      local_similarity = m["similarity"]
      if local_similarity > max_similarity
        max_similarity = m["similarity"]
        hashes = [m["hash"]]
      elsif local_similarity == max_similarity
        hashes.push(m["hash"])
      end
    end

    # Then we get the maximum score among the hashes
    hashes.each do |h|
      local_score = AerospikeMethods::get_value(@aerospike, @aerospike_namespace, @aerospike_set_scores, h, "score")
      score = local_score if local_score > score
      @logger.info(score.to_s)
    end

    (score * max_similarity).round
  end

  public
  def filter(event)

    @file_path = event.get(@file_field)
    fuzzy_info = {"pehash" => { }, "ssdeep" => { }, "sdhash" => { }}

    begin
      @hash = Digest::SHA2.new(256).hexdigest File.read @file_path
    rescue Errno::ENOENT => ex
      @logger.error(ex.message)
    end

    starting_time = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    @pehash, @ssdeep, @sdhash = get_fuzzy_hashes_from_file

    fuzzy_info["pehash"] = get_pehash_info
    fuzzy_info["ssdeep"] = get_ssdeep_info
    fuzzy_info["sdhash"] = get_sdhash_info

    matches = fuzzy_info["pehash"]["Matches"].push(fuzzy_info["ssdeep"]["Matches"]).push(fuzzy_info["sdhash"]["Matches"]).flatten

    score = get_fuzzy_score(matches)

    global_score = AerospikeMethods::get_value(@aerospike, @aerospike_namespace, @aerospike_set_scores, @hash, "score")

    add_hashes_to_aerospike if score > 0 or (!global_score.nil? and global_score > 0)

    ending_time  = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    elapsed_time = (ending_time - starting_time).round(1)

    event.set(@latency_name, elapsed_time)
    event.set(@target, fuzzy_info)
    event.set(@score_name, score)

    AerospikeMethods::update_malware_hash_score(@aerospike, @aerospike_namespace, @aerospike_set_scores, @hash, @score_name, score, "sb")

    # filter_matched should go in the last line of our successful code
    filter_matched(event)

  end  # def filter(event)
end # class LogStash::Filters::Fuzzy

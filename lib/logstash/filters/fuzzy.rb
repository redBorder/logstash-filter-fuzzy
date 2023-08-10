# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"

require 'json'
require 'aerospike'
require 'text'

require_relative "util/aerospike_config"

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
    @aerospike_server = AerospikeConfig::servers if @aerospike_server.empty?
    @aerospike_server = @aerospike_server.sample if @aerospike_server.class.to_s == "Array"  
    @aerospike = nil
    register_aerospike
  end # def register

  private

  def register_aerospike
    begin
      host,port = @aerospike_server.split(":")
      @aerospike = Client.new(Host.new(host, port))
    rescue Aerospike::Exceptions::Aerospike => ex
      @aerospike = nil
      @logger.error(ex.message)
    end
  end

  # Get fuzzy hashes from files.
  #
  # This method needs a python script (hasher.py) to get the aforementioned hashes.
  #
  # There are three kinds of hashes that can be returned from hasher.py:
  #
  # 1. peHash: Hash from PE files.
  # PE format is a file format for executables, object code, DLLs and
  # others used in 32-bit and 64-bit versions of Windows operating systems.
  #
  # 2. ssdeep.
  #
  # 3. sdHash.
  #
  #@return Array with hashes [pe_hash, ssdeep, sdhash].
  def get_fuzzy_hashes_from_file

    @logger.info("Calculating fuzzy hashes from #{File.basename(@file_path)}.")

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

  # Get fuzzy records from Aerospike
  #
  # @return [Aerospike::Recordset, nil] Aerospike::Recordset or nil if there is no records in Aerospike.
  def get_fuzzy_records
    @logger.info("Getting fuzzy records from Aerospike.")
    records = nil
    begin
      stmt = Statement.new(@aerospike_namespace, @aerospike_set_fuzzy_hash)
      records = @aerospike.query(stmt).records
      records = Array.new(records.size) { records.pop }
    rescue Aerospike::Exceptions::Aerospike => ex
      @logger.error("Failed when trying to get records.")
      @logger.error(ex.message)
    end
    records
  end

  # Get file score from Aerospike
  #
  # @param hash - Key to search for the score in Aerospike
  # @return [Integer,nil] Score or nil if there is no score in Aerospike
  def get_hash_score(hash)
    @logger.info("Getting hash score from hash #{hash}.")
    begin
      key = Key.new(@aerospike_namespace, @aerospike_set_scores, hash)
      record = @aerospike.get(key,[],Policy.new)

      record.bins["score"] unless record.nil?
    rescue Aerospike::Exceptions::Aerospike => ex
      @logger.error(ex.message)
      nil
    end
  end

  # Get matches, if any, from file peHash and peHashes stored in Aerospike
  #
  # @return a dictionary (hash) with pehash matches with the form {"hash" => key, "pehash" => pe_hash, "similarity" => 100}
  #
  def get_pehash_matches
    @logger.info("Getting peHash matches.")
    pehash_info = {"peHash" => @pehash, "Matches" => "none"}

    if @pehash == ''
      return pehash_info
    end

    @records.each do |record|
      next unless record.key
      key = record.key.user_key
      if @hash != key  #Avoid duplicate events
        local_pe_hash = record.bins["pehash"]
        if local_pe_hash and local_pe_hash == @pehash
          pehash_info["Matches"] = [] if pehash_info["Matches"].instance_of? String
          pehash_info["Matches"].push({"hash" => key, "pehash" => local_pe_hash, "similarity" => 100})
        end
      end
    end
    pehash_info
  end

  # Get matches, if any, from file sdHash and sdHashes stored in Aerospike
  #
  # @return a dictionary (hash) with sdhash matches with the form {"hash" => key, "sdhash" => sd_hash, "similarity" => similarity}
  #
  def get_sdhash_matches
    @logger.info("Getting sdHash matches.")
    sdhash_info = {"sdHash" => @sdhash, "Matches" => "none"}

    unless File.exist?(@sdhash_bin)
      @logger.error("Sdhash binary is not in #{@sdhash_bin}.")
      sdhash_info
    end

    if @sdhash == ''
      return sdhash_info
    end

    sdhashes = []
    @records.each do |record|
      next unless record.key
      key = record.key.user_key
      if @hash != key  #Avoid duplicate events
        local_sd_hash = record.bins["sdhash"]
        sdhashes.push local_sd_hash if local_sd_hash
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
        sdhash_info["Matches"] = [] if sdhash_info["Matches"].instance_of? String
        sdhash_info["Matches"].push({"hash" => hash, "similarity" => similarity})
      end
    end
    sdhash_info
  end

  # Get matches, if any, from file ssdeepHash and ssdeepHashes stored in Aerospike
  #
  # @return a dictionary (hash) with ssdeep matches with the form {"hash" => key, "ssdeep" => ssdeep_hash, "similarity" => similarity}
  #
  def get_ssdeep_matches
    @logger.info("Getting ssdeep matches.")
    ssdeep_info = {"ssdeep" => @ssdeep, "Matches" => "none"}

    if @ssdeep == ''
      return ssdeep_info
    end

    @records.each do |record|
      next unless record.key
      key = record.key.user_key
      if @hash != key  #Avoid duplicate events
        local_ssdeep = record.bins["ssdeep"]
        if local_ssdeep
          similarity = compare_ssdeep(@ssdeep,local_ssdeep)
          if similarity > @threshold
            ssdeep_info["Matches"] = [] if ssdeep_info["Matches"].instance_of? String
            ssdeep_info["Matches"].push({"hash" => key, "ssdeep" => local_ssdeep ,"similarity" => similarity})
          end
        end
      end
    end

    ssdeep_info
  end

  # Get ssdeep similarity between two ssdeep hashes
  #
  # @param fh1 - First fuzzy hash
  # @param fh2 - Second fuzzy hash
  # @return Integer - ssdeep similarity
  #
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

  # Calculate how different are two strings using Levenshtein Distance
  #
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

  # Store fuzzy hashes in Aerospike
  #
  def add_fuzzy_hashes_to_aerospike

    @logger.info("Storing fuzzy hashes from #{@hash} in Aerospike.")
    begin
      bins = []

      bins.push(Bin.new("pehash", @pehash))
      bins.push(Bin.new("ssdeep", @ssdeep))
      bins.push(Bin.new("sdhash", @sdhash))

      key = Key.new(@aerospike_namespace,@aerospike_set_fuzzy_hash,@hash)

      policy = WritePolicy.new
      policy.expiration = @ttl_fuzzy

      @aerospike.put(key,bins,policy)
    rescue Aerospike::Exceptions::Aerospike => ex
      @logger.error(ex.message)
    end
  end

  # Get fuzzy score
  #
  # @param matches - Array with matches
  # @return score - Integer with the maximum similarity between the fuzzy algorithms.
  def get_fuzzy_score(matches)
    score = 0

    #First we get a list of hashes with the maximum similarity
    hashes = []
    max_similarity = 0

    matches.each do |m|
      if !m["similarity"].nil? && m["similarity"].is_a?(Numeric)
        local_similarity = m["similarity"]
        if local_similarity > max_similarity
          max_similarity = m["similarity"]
          hashes = [m["hash"]]
        elsif local_similarity == max_similarity
          hashes.push(m["hash"])
        end
      end
    end

    # Then we get the maximum score among the hashes
    hashes.each do |h|
      begin
        local_score = get_hash_score(h)
        score = local_score if local_score > score
        @logger.info(score.to_s)
      rescue
        @logger.error("Error while fetching score from Aerospike.")
      end
    end

    (score * max_similarity).round
  end

  public
  def filter(event)

    # Solve the problem that happen when:
    # at time of registering the plugin the
    # aerospike was not there
    register_aerospike if @aerospike.nil?

    @file_path = event.get(@file_field)
    @logger.info("[#{@target}] processing #{@path}")

    fuzzy_info = {"pehash" => { }, "ssdeep" => { }, "sdhash" => { }}

    @hash = event.get('sha256')

    if @hash.nil?
      begin
        @hash = Digest::SHA2.new(256).hexdigest File.read @file_path
        event.set('sha256', @hash)
      rescue Errno::ENOENT => ex
        @logger.error(ex.message)
      end
    end

    starting_time = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    @pehash, @ssdeep, @sdhash = get_fuzzy_hashes_from_file

    @records = get_fuzzy_records

    fuzzy_info["pehash"] = get_pehash_matches
    fuzzy_info["ssdeep"] = get_ssdeep_matches
    fuzzy_info["sdhash"] = get_sdhash_matches

    matches = []
    matches.push(fuzzy_info["pehash"]["Matches"]) unless fuzzy_info["pehash"]["Matches"].instance_of? String
    matches.push(fuzzy_info["ssdeep"]["Matches"]) unless fuzzy_info["ssdeep"]["Matches"].instance_of? String
    matches.push(fuzzy_info["sdhash"]["Matches"]) unless fuzzy_info["sdhash"]["Matches"].instance_of? String
    matches.flatten unless matches.empty?

    score = get_fuzzy_score(matches)

    global_score = get_hash_score(@hash)

    add_fuzzy_hashes_to_aerospike if score > 0 or (!global_score.nil? and global_score > 0)

    ending_time  = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    elapsed_time = (ending_time - starting_time).round(1)

    event.set(@latency_name, elapsed_time)
    event.set(@target, fuzzy_info)
    event.set(@score_name, score)


    # filter_matched should go in the last line of our successful code
    filter_matched(event)

  end  # def filter(event)
end # class LogStash::Filters::Fuzzy

Gem::Specification.new do |s|
  s.name = 'logstash-filter-fuzzy'
  s.version = '0.0.6'
  s.licenses = ['Apache-2.0']
  s.summary = "plugin to get malicious fuzzy score from files pipeline"
  s.description = "This gem is a Logstash plugin required to be installed on top of the Logstash core pipeline using $LS_HOME/bin/logstash-plugin install gemname. This gem is not a stand-alone program"
  s.authors = ["redBorder"]
  s.email = 'systems@redborder.com'
  s.homepage = "https://www.redborder.com"
  s.require_paths = ["lib"]

  # Files
  s.files = Dir['lib/**/*','spec/**/*','vendor/**/*','*.gemspec','*.md','CONTRIBUTORS','Gemfile','LICENSE','NOTICE.TXT']
   # Tests
  s.test_files = s.files.grep(%r{^(test|spec|features)/})

  # Special flag to let us know this is actually a logstash plugin
  s.metadata = { "logstash_plugin" => "true", "logstash_group" => "filter" }

  # Gem dependencies
  s.add_runtime_dependency "logstash-core-plugin-api",  "~> 2.0"
  s.add_runtime_dependency 'digest',                    "3.1.0"
  s.add_runtime_dependency 'json',                      "1.8.6"
  s.add_runtime_dependency 'text',                      "1.3.1"
  s.add_runtime_dependency 'aerospike',                 "2.5.1"
  s.add_development_dependency 'logstash-devutils',     "2.4.0"
end

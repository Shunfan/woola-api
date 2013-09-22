require './woola'
require 'resque/server'

run Rack::URLMap.new \
  "/"       => Woola,
  "/resque" => Resque::Server.new

ENV['RACK_ENV'] = 'test'

require 'minitest/autorun'
require 'rack/test'

require './woola'

require 'json'

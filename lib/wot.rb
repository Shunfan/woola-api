require 'json'
require 'faraday'

class WOT
  @queue = :woola_api_wot

  attr_reader :host

  def initialize(host)
    @host = host
    @connection = Faraday.new(:url => 'http://api.mywot.com')
  end

  def self.perform(url)
    host = URI(url).host
    wot = new(host)

    wot_report = wot.get_report
    tw = wot_report[wot.host]["0"] # tw stands for trustworthy

    if tw
      $r.hmset("wot:#{host}",
               "tw_reputation", tw[0],
               "tw_confidence", tw[1])
    end
  end

  def get_report
    data = {:hosts => "#{@host}/", :key => WOTAPI}
    JSON.parse(@connection.get('/0.4/public_link_json2', data).body)
  end
end

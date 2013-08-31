require 'json'
require 'faraday'

class VirusTotal
  @queue = :woola_api_virustotal

  API_KEY = '57f6cc666813101cd1245e8188921df5f26a79ae40527876a273b03ae747c445'

  def initialize(url)
    @url = url
    @connection = Faraday.new(:url => 'http://www.virustotal.com')
  end

  def self.perform(url)
    vt_report = new(url).get_report

    if vt_report['verbose_msg'].include?('Scan finished')
      scans = vt_report['scans']
      scans.keep_if {|k, v| v['detected'] == true}

      detected_scans = {}
      scans.each {|k, v| detected_scans[k] = v['result']} if !scans.empty?

      $r.hmset("virustotal:#{url}", detected_scans.flatten) if !detected_scans.empty?
    end
  end

  def get_report
    data = {:resource => @url, :scan => 1, :apikey => API_KEY}
    JSON.parse(@connection.post('/vtapi/v2/url/report', data).body)
  end
end

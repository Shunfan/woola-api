require 'excon'
require 'nokogiri'

class URL
  @queue = :woola_api_url

  attr_reader :scheme, :domain, :response

  def initialize(url)
    @url = url
    @scheme = URI(url).scheme
    @domain = URI(url).host
    @head = get_head
    @response = get_response
    @document = parse_html
  end

  def self.perform(url)
    url = new(url)

    $r.hmset("url:#{url}",
             "scheme",       url.scheme,
             "domain",       url.domain,
             "redirect",     url.redirect,
             "content_type", url.content_type,
             "status",       url.status,
             "title",        url.title)
  end

  def to_s
    @url
  end

  def redirect
    @head.headers['Location']
  end

  def content_type
    if status == 200
      @response.headers['Content-Type']
    end
  end

  def status
    if !@response.nil?
      @response.status
    end
  end

  def title
    if !@document.nil?
      @document.title
    end
  end

  protected

  def get_head
    Excon.head(@url)
  end

  def head_status
    @head.status
  end

  def head_content_type
    if head_status == 200
      @head.headers['Content-Type']
    end
  end

  def get_response
    if redirect
      URL.new(redirect).response
    elsif (!head_content_type.nil? && head_content_type.include?('text/html')) \
      || head_status == 405
      Excon.get(@url)
    end
  end

  def parse_html
    if !@response.nil?
      html = @response.body
      Nokogiri::HTML(html)
    end
  end
end

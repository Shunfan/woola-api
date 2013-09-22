require 'json'
require 'redis'
require 'resque'
require 'sinatra/base'

require './config'
require './lib/url'
require './lib/wot'
require './lib/virustotal'

class Woola < Sinatra::Base
  $r = Redis.new

  Resque.redis = $r
  Resque.redis.namespace = 'resque:woola'

  # ALLOW cross domain access for ajax.
  before do
    headers['Access-Control-Allow-Origin'] = '*'
    headers['Access-Control-Allow-Methods'] = 'GET, POST, PATCH, PUT'
  end

  # Shorten long url.
  # Parameters: URL.
  # Return: Slug, Url, Clicks, Created_at, Updated_at
  post '/slugs' do
    content_type :json

    url = params[:url]

    if !(UrlRegExp === url) || SlugUrlRegExp === url # Avoid shortening url that has been shortened.
      JSON.pretty_generate({message: "URL Invalid"})
    else
      url = unified_url(url)

      if $r.exists("url:#{url}")
        host = URI(url).host

        wot = {wot: $r.hgetall("wot:#{host}")}
        virustotal = {virustotal: $r.hgetall("virustotal:#{url}")}

        JSON.pretty_generate($r.hgetall("url:#{url}").merge(wot).merge(virustotal))
      else
        begin
          slug = random_slug
        end while $r.exists("slug:#{slug}")

        $r.hmset("url:#{url}",
                 "slug",       slug,
                 "url",        url,
                 "clicks",     0,
                 "created_at", Time.now.to_i,
                 "updated_at", Time.now.to_i)

        $r.set("slug:#{slug}", url)

        Resque.enqueue(URL, url)
        Resque.enqueue(WOT, url)
        Resque.enqueue(VirusTotal, url)

        JSON.pretty_generate($r.hgetall("url:#{url}"))
      end
    end
  end

  # GET the information of the slug.
  # Parameters: Slug.
  get '/slugs/:slug' do |slug|
    content_type :json

    if !(SlugRegExp === slug)
      JSON.pretty_generate({message: "Slug Invalid"})
    elsif !$r.exists("slug:#{slug}")
      JSON.pretty_generate({message: "Not Found"})
    else
      url = $r.get("slug:#{slug}")

      host = URI(url).host

      wot = {wot: $r.hgetall("wot:#{host}")}
      virustotal = {virustotal: $r.hgetall("virustotal:#{url}")}

      JSON.pretty_generate($r.hgetall("url:#{url}").merge(wot).merge(virustotal))
    end
  end

  # Update the slug info.
  # Parameters: Slug.
  get '/slugs/:slug/update' do |slug|
    content_type :json

    if !(SlugRegExp === slug)
      JSON.pretty_generate({message: "Slug Invalid"})
    elsif !$r.exists("slug:#{slug}")
      JSON.pretty_generate({message: "Not Found"})
    else
      url = $r.get("slug:#{slug}")

      if Time.now.to_i - 300 < $r.hget("url:#{url}", "updated_at").to_i
        JSON.pretty_generate({message: "Update Failed"})
      else
        $r.hset("url:#{url}", "updated_at", Time.now.to_i)

        Resque.enqueue(URL, url)
        Resque.enqueue(WOT, url)
        Resque.enqueue(VirusTotal, url)

        JSON.pretty_generate({message: "Update Scheduled"})
      end
    end
  end

  not_found do
    JSON.pretty_generate({message: "404"})
  end

  helpers do
    def random_slug
      slug = ''
      SlugLength.times do
        random = rand(36).to_s(36)
        if SlugCaseSensitivity && [true, false].sample
          random.upcase!
        end
        slug << random
      end
      slug 
    end

    def unified_url(url)
      if !url.start_with?('http')
        url = "http://#{url}"
      end
      if %r{^(https?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})?$} === url
        url = "#{url}/"
      end
      url
    end
  end
end

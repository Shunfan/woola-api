require 'json'
require 'redis'
require 'digest'
require 'resque'
require 'sinatra/base'

require './config'
require './lib/url'
require './lib/wot'
require './lib/virustotal'

class App < Sinatra::Base
  set :public_folder, 'static'

  $r = Redis.new
  Resque.redis = $r
  Resque.redis.namespace = 'resque:woola'

  # ALLOW cross domain access for ajax.
  before do
    headers['Access-Control-Allow-Origin'] = '*'
    headers['Access-Control-Allow-Methods'] = 'GET, POST, PATCH, PUT'
  end

  # Only for test
  get '/' do
    send_file 'static/index.html'
  end

  # GET the information of the slug.
  # Parameters: Slug.
  get '/slugs/:slug' do |slug|
    content_type :json

    if !(SlugRegExp === slug)
      JSON.pretty_generate({message: "Slug Invalid"})
    else
      if !$r.exists("slug:#{slug}")
        JSON.pretty_generate({message: "Not Found"})
      else
        url = $r.get("slug:#{slug}")
        host = URI(url).host

        virustotal = {virustotal: $r.hgetall("virustotal:#{url}")}
        wot = {wot: $r.hgetall("wot:#{host}")}

        JSON.pretty_generate(
          {url: url}.merge($r.hgetall("url:#{url}")).merge(virustotal).merge(wot)
        )
      end
    end
  end

  # POST a long url, then a short slug of the url will be returned.
  # Parameters: Url.
  post '/slugs' do
    content_type :json

    if !(UrlRegExp === params[:url]) || SlugUrlRegExp === params[:url] # Avoid shortening url that has been shortened.
      JSON.pretty_generate({message: "URL Invalid"})
    else
      url = unified_url(params[:url])

      if $r.exists("url:#{url}")
        host = URI(url).host

        virustotal = {virustotal: $r.hgetall("virustotal:#{url}")}
        wot = {wot: $r.hgetall("wot:#{host}")}

        JSON.pretty_generate(
          {url: url}.merge($r.hgetall("url:#{url}")).merge(virustotal).merge(wot)
        )
      else
        begin
          slug = random_slug
        end while $r.exists("slug:#{slug}")

        $r.hmset("url:#{url}",
                 "slug",       slug,
                 "clicks",     0,
                 "created_at", Time.now.to_i,
                 "updated_at", Time.now.to_i)

        $r.set("slug:#{slug}", url)

        Resque.enqueue(URL, url)
        Resque.enqueue(WOT, url)
        Resque.enqueue(VirusTotal, url)

        JSON.pretty_generate(
          {url: url}.merge($r.hgetall("url:#{url}"))
        )
      end
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

      if Time.now.to_i - 1 < $r.hget("url:#{url}", "updated_at").to_i
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

  # Get the token of a user.
  # Parameters: Username OR Email, Password.
  # Return: ID, Username, Email, Token.
  get '/users' do
    content_type :json

    if UsernameRegExp === params[:account]
      id = $r.get("username:#{params[:account]}")

      if !id
        JSON.pretty_generate({message: BadLoginMessage})
      elsif !validate_user(id, params[:password])
        JSON.pretty_generate({message: BadLoginMessage})
      else
        user = $r.hgetall("user:#{id}")
        JSON.pretty_generate({id: id}.merge({username: user["username"], email: user["email"], token: user["token"]}))
      end
    elsif EmailRegExp === params[:account]
      id = $r.get("email:#{params[:account]}")

      if !id
        JSON.pretty_generate({message: BadLoginMessage})
      elsif !validate_user(id, params[:password])
        JSON.pretty_generate({message: BadLoginMessage})
      else
        user = $r.hgetall("user:#{id}")
        JSON.pretty_generate({id: id}.merge({username: user["username"], email: user["email"], token: user["token"]}))
      end
    else
      JSON.pretty_generate({message: BadLoginMessage})
    end
  end

  # Register an account.
  # Parameters: Username, Email, Password.
  post '/users' do
    content_type :json

    if !(UsernameRegExp === params[:username])
      JSON.pretty_generate({message: InvalidUsernameMessage})
    elsif !(EmailRegExp === params[:email])
      JSON.pretty_generate({message: InvalidEmailMessage})
    elsif !(PasswordRegExp === params[:password])
      JSON.pretty_generate({message: InvalidPasswordMessage})
    elsif $r.exists("username:#{params[:username]}")
      JSON.pretty_generate({message: ExistUsernameMessage})
    elsif $r.exists("email:#{params[:email]}")
      JSON.pretty_generate({message: ExistEmailMessage})
    else
      email = params[:email]
      username = params[:username]

      token = random_token
      first_salt = random_salt
      last_salt = random_salt

      password = hash_password(params[:password], first_salt, last_salt)

      if !$r.exists("user_id")
        $r.set("user_id", "0")
      end

      id = $r.get("user_id").to_i + 1

      $r.hmset("user:#{id}",
               "username",     username,
               "email",        email,
               "first_salt",   first_salt,
               "last_salt",    last_salt,
               "password",     password,
               "token",        token,
               "created_at",   Time.now.to_i)

      $r.set("username:#{username}", id)
      $r.set("email:#{email}", id)
      $r.set("token:#{token}", id)

      $r.incr("user_id")

      JSON.pretty_generate({id: id}.merge($r.hgetall("user:#{id}")))
    end
  end

  # Update user's information, password or token.
  # Parameters: Token and Password are required.
  patch '/users' do
    content_type :json

    id = $r.get("token:#{params[:token]}")

    if !id
      JSON.pretty_generate({message: AccessDeniedMessage})
    elsif !validate_user(id, params[:password])
      JSON.pretty_generate({message: AccessDeniedMessage})
    elsif !params[:username] && !params[:email] && !params[:password]
      JSON.pretty_generate({message: BlankParamsMessage})
    elsif params[:username] && !(UsernameRegExp === params[:username])
      JSON.pretty_generate({message: InvalidUsernameMessage})
    elsif params[:email] && !(EmailRegExp === params[:email])
      JSON.pretty_generate({message: InvalidEmailMessage})
    elsif params[:new_password] && !(PasswordRegExp === params[:new_password])
      JSON.pretty_generate({message: InvalidPasswordMessage})
    else
      user = $r.hgetall("user:#{id}")

      if params[:username] != user["username"] && $r.exists("username:#{params[:username]}")
        JSON.pretty_generate({message: ExistUsernameMessage})
      elsif params[:email] != user["email"] && $r.exists("email:#{params[:email]}")
        JSON.pretty_generate({message: ExistEmailMessage})
      else
        message = {}

        if params[:username] && params[:username] != user["username"]
          $r.hset("user:#{id}", "username", params[:username])
          $r.set("username:#{params[:username]}", id)
          $r.del("username:#{user["username"]}")

          message[:username] = params[:username]
        end

        if params[:email] && params[:email] != user["email"]
          $r.hset("user:#{id}", "email", params[:email])
          $r.set("email:#{params[:email]}", id)
          $r.del("email:#{user["email"]}")

          message[:email] = params[:email]
        end

        if params[:new_password]
          password = hash_password(params[:new_password], user["first_salt"], user["last_salt"])
          $r.hset("user:#{id}", "password", password)

          message[:new_password] = "Success"
        end

        JSON.pretty_generate(message)
      end
    end
  end


  # Regenerate access token.
  # Parameters: Original access token, Password.
  put '/users/token' do
    content_type :json

    id = $r.get("token:#{params[:token]}")

    if !id
      JSON.pretty_generate({message: AccessDeniedMessage})
    elsif !validate_user(id, params[:password])
      JSON.pretty_generate({message: AccessDeniedMessage})
    else
      token = random_token

      $r.hset("user:#{id}", "token", token)

      $r.set("token:#{token}", id)
      $r.del("token:#{params[:token]}")

      JSON.pretty_generate({token: token})
    end
  end

  not_found do
    '404 Not Found'
  end

  helpers do
    def validate_user(id, password)
      user = $r.hgetall("user:#{id}")
      input_password = hash_password(password, user["first_salt"], user["last_salt"])
      input_password == user["password"] ? true : false
    end

    def hash_password(password, first_salt, last_salt)
      Digest::SHA2.hexdigest(first_salt + password + last_salt)
    end

    def check_params(*required)
      required.each{|p|
        params[p].strip! if params[p] and params[p].is_a? String
        if !params[p] or (p.is_a? String and params[p].length == 0)
          return false
        end
      }
      true
    end

    def random_slug
      slug = ''
      SlugLength.times do
        random = rand(36).to_s(36)
        if [true, false].sample
          random.upcase!
        end
        slug << random
      end
      slug 
    end

    def random_salt
      salt = ''
      SaltLength.times do
        random = rand(36).to_s(36)
        if [true, false].sample
          random.upcase!
        end
        salt << random
      end
      salt
    end

    def random_token
      token = ''
      TokenLength.times do
        random = rand(36).to_s(36)
        token << random
      end
      token
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

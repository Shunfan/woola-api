require './test/test_helper'

include Rack::Test::Methods

def app
  Woola
end

describe "Woola" do
  it "should successfully return a slug when a url is posted" do
    post '/slugs', params = {:url => "http://example.com/"}

    assert_equal last_response.status, 200

    response = JSON.parse(last_response.body)

    response.must_be_instance_of(Hash)
    response["url"].wont_be_nil
    response["slug"].wont_be_nil
    response["created_at"].wont_be_nil
    response["updated_at"].wont_be_nil
  end
end

require "action_dispatch"

RSpec.describe "Content Security Policy nonce" do
  def app_with(env_config, page: "<html><head></head><body></body></html>")
    Rack::Builder.new do
      use(Class.new do
        define_method(:initialize) { |app| @app = app }
        define_method(:call) { |env| @app.call(env.merge(env_config)) }
      end)
      use ActionDispatch::ContentSecurityPolicy::Middleware
      use Rack::Tracker do
        handler :google_analytics4, { tracker: "G-XXXXXXX" }
      end
      run ->(env) { [200, Rack::Headers["content-type" => "text/html"], [page.respond_to?(:call) ? page.call(env) : page]] }
    end
  end

  let(:csp) do
    {
      "action_dispatch.content_security_policy" => ActionDispatch::ContentSecurityPolicy.new { |policy| policy.script_src :self },
      "action_dispatch.content_security_policy_nonce_generator" => ->(request) { "abc123" },
      "action_dispatch.content_security_policy_nonce_directives" => %w[script-src],
    }
  end

  def scripts(body)
    body.scan(/<script\b[^>]*>/)
  end

  it "puts the request's nonce on every script it injects, and in the policy header" do
    response = Rack::MockRequest.new(app_with(csp)).get("/")
    expect(scripts(response.body).size).to eq 3
    expect(scripts(response.body)).to all(include('nonce="abc123"'))
    expect(response.headers["content-security-policy"]).to include("'nonce-abc123'")
  end

  it "reuses the nonce the page already used" do
    page = ->(env) { %(<html><head><script nonce="#{ActionDispatch::Request.new(env).content_security_policy_nonce}"></script></head><body></body></html>) }
    calls = 0
    config = csp.merge("action_dispatch.content_security_policy_nonce_generator" => ->(request) { "nonce#{calls += 1}" })
    response = Rack::MockRequest.new(app_with(config, page:)).get("/")
    expect(scripts(response.body)).to all(include('nonce="nonce1"'))
    expect(response.headers["content-security-policy"]).to include("'nonce-nonce1'")
  end

  it "adds no nonce when the app doesn't generate them" do
    response = Rack::MockRequest.new(app_with({})).get("/")
    expect(scripts(response.body).size).to eq 3
    expect(response.body).not_to include("nonce=")
  end
end

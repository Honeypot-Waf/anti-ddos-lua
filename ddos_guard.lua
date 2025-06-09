--]]

-- Professional L7 DDoS Guard Module v3.0.0
-- Advanced HTTP flood, Slowloris va bot defend
-- Muallif: Azizbek Raxmatullayev
-- Sana: 2025-04-05

local _M = {
    _VERSION = "3.0.0"
}

local guard = ngx.shared.ddos_guard
local challenge_dict = ngx.shared.ddos_challenge
local blocked_dict = ngx.shared.ddos_blocked
local metrics_dict = ngx.shared.ddos_metrics

local resty_sha256 = require("resty.sha256")
local str = require("resty.string")
local cjson = require("cjson")
local bit = require("bit")

-- # Smart IP UZ Bypass Layer 
local UZ_IP_RANGES = {
  
  -- Local networks (private IP ranges)
  {network = "10.0.0.0", mask = 8, name = "Private-A"},
  {network = "172.16.0.0", mask = 12, name = "Private-B"},
  {network = "192.168.0.0", mask = 16, name = "Private-C"},
  {network = "127.0.0.0", mask = 8, name = "Localhost"}
}

local hmac_secret = nil
local geoip_enabled = false

local config = {
    enabled = true,
    
    challenge_timeout = 3000,          -- Token second
    challenge_difficulty = 5000,      -- js challenge difficulty (ms)
    
    -- # Rate limiting defend
    rate_limit_window = 5,           -- 5 second window
    rate_limit_requests = 60,        -- max 60 requests in 5s
    block_duration = 600,            -- 10 minute block

    -- # Slowloris defend
    slowloris_content_limit = 128,   -- Max Content-Length
    slowloris_timeout = 10,          -- Request timeout (second)

    -- # URI entropy defend
    uri_entropy_threshold = 5.0,     -- Max entropy
    
    -- #  Dangerous patterns
    dangerous_patterns = {
        "wp%-login%.php",
        "xmlrpc%.php", 
        "wp%-admin",
        "phpmyadmin",
        "admin/login",
        "administrator",
        "%.env",
        "config%.php"
    }
}

-- # 
local function init_metrics()
    if not metrics_dict:get("requests_total") then
        metrics_dict:set("requests_total", 0)
        metrics_dict:set("requests_blocked", 0) 
        metrics_dict:set("challenges_sent", 0)
        metrics_dict:set("uz_bypassed", 0)
        metrics_dict:set("slowloris_blocked", 0)
        metrics_dict:set("bot_blocked", 0)
    end
end

-- # Client IP detection
local function get_client_ip()
    local xff = ngx.var.http_x_forwarded_for
    if xff then
        local ip = string.match(xff, "([^,]+)")
        if ip then
            return string.gsub(ip, "%s+", "") -- Remove spaces
        end
    end
    
    local xri = ngx.var.http_x_real_ip
    if xri then
        return xri
    end
    
    return ngx.var.remote_addr
end

-- # Smart UZ Bypass Layer 

local function ip_to_int(ip_str)
    if not ip_str then return nil end
    
    local parts = {}
    for part in string.gmatch(ip_str, "%d+") do
        table.insert(parts, tonumber(part))
    end
    
    if #parts ~= 4 then return nil end
    
    return bit.lshift(parts[1], 24) + bit.lshift(parts[2], 16) + bit.lshift(parts[3], 8) + parts[4]
end

local function ip_in_cidr(ip_int, network_int, mask)
    if not ip_int or not network_int or not mask then
        return false
    end
    
    local subnet_mask = bit.lshift(0xFFFFFFFF, (32 - mask))
    subnet_mask = bit.band(subnet_mask, 0xFFFFFFFF)
    
    return bit.band(ip_int, subnet_mask) == bit.band(network_int, subnet_mask)
end

local function is_uzbek_ip(ip)
    if not ip then return false end
    
    local bypass = ngx.var.ddos_bypass
    if bypass == "1" then
        metrics_dict:incr("uz_bypassed", 1)
        return true
    end
    
    local ip_int = ip_to_int(ip)
    if not ip_int then return false end
    
    for _, range_info in ipairs(UZ_IP_RANGES) do
        local network_int = ip_to_int(range_info.network)
        if network_int and ip_in_cidr(ip_int, network_int, range_info.mask) then
            ngx.log(ngx.INFO, "UZ IP detected: ", ip, " in range: ", range_info.network, "/", range_info.mask, " (", range_info.name, ")")
            metrics_dict:incr("uz_bypassed", 1)
            return true
        end
    end
    
    -- PRIORITY 3: Special cases and local networks
    -- Private networks (often used in UZ local infrastructure)
    if string.match(ip, "^10%.") or 
       string.match(ip, "^172%.1[6-9]%.") or string.match(ip, "^172%.2[0-9]%.") or string.match(ip, "^172%.3[0-1]%.") or
       string.match(ip, "^192%.168%.") or
       string.match(ip, "^127%.") then
        metrics_dict:incr("uz_bypassed", 1)
        return true
    end
    
    return false
end

-- # HMAC-SHA256 token generator
local function create_token(ip, timestamp)
    if not hmac_secret then
        return nil
    end
    
    local data = ip .. ":" .. timestamp
    local sha256 = resty_sha256:new()
    
    -- HMAC generator
    local key_sha = resty_sha256:new()
    key_sha:update(hmac_secret)
    local key_hash = key_sha:final()
    
    sha256:update(key_hash .. data)
    local hash = sha256:final()
    
    return str.to_hex(hash)
end

-- # Token'ni check
local function verify_token(ip, token, timestamp)
    if not token or not timestamp then
        return false
    end
    
    local current_time = ngx.time()
    timestamp = tonumber(timestamp)
    
    -- Token date check
    if current_time - timestamp > config.challenge_timeout then
        return false
    end
    
    local expected_token = create_token(ip, timestamp)
    return expected_token == token
end

-- # URI entropy 
local function calculate_uri_entropy(uri)
    if not uri or #uri == 0 then
        return 0
    end
    
    local char_count = {}
    local total_chars = #uri
    
    for i = 1, total_chars do
        local char = string.sub(uri, i, i)
        char_count[char] = (char_count[char] or 0) + 1
    end
    
    local entropy = 0
    for char, count in pairs(char_count) do
        local probability = count / total_chars
        entropy = entropy - (probability * math.log(probability) / math.log(2))
    end
    
    return entropy
end

local function check_dangerous_patterns(uri)
    if not uri then
        return false
    end
    
    for _, pattern in ipairs(config.dangerous_patterns) do
        if string.match(uri, pattern) then
            return true
        end
    end
    
    return false
end

-- # Slowloris attack detection
local function check_slowloris()
    local headers = ngx.req.get_headers()
    
    -- Expect: 100-continue Content-Length
    if headers["expect"] and string.lower(headers["expect"]) == "100-continue" then
        local content_length = tonumber(headers["content-length"] or "0")
        if content_length > 0 and content_length < config.slowloris_content_limit then
            return true
        end
    end
    
    -- slow request time
    local request_time = ngx.var.request_time
    if request_time and tonumber(request_time) > config.slowloris_timeout then
        return true
    end
    
    -- Connection header manipulation
    local connection = headers["connection"]
    if connection and string.lower(connection) == "keep-alive" then
        local keep_alive = headers["keep-alive"]
        if keep_alive and string.match(keep_alive, "timeout=(%d+)") then
            local timeout = tonumber(string.match(keep_alive, "timeout=(%d+)"))
            if timeout and timeout > 300 then 
                return true
            end
        end
    end
    
    return false
end

-- # Rate limit
local function check_rate_limit(ip)
    local key = "rate:" .. ip
    local current_time = ngx.time()
    
    -- Atomic increment
    local count, err = guard:incr(key, 1, 0, config.rate_limit_window)
    if not count then
        ngx.log(ngx.ERR, "[DDOS_GUARD] Rate limit error: ", err)
        return false
    end

    -- Rate limit check
    if count > config.rate_limit_requests then
        -- Block IP
        blocked_dict:set(ip, current_time, config.block_duration)
        ngx.log(ngx.WARN, "[DDOS_GUARD] Rate limit exceeded, IP blocked: ", ip, " (", count, " requests)")
        return true
    end
    
    return false
end

-- # User-Agent and bot detection
local function is_bot_request()
    local user_agent = ngx.var.http_user_agent
    if not user_agent then
        return true -- no User-Agent header, treat as bot
    end

    -- Known bot patterns
    local bot_patterns = {
        "bot", "crawler", "spider", "scraper", "curl", "wget", 
        "python", "perl", "ruby", "java", "go%-http", "scanner"
    }
    
    local ua_lower = string.lower(user_agent)
    for _, pattern in ipairs(bot_patterns) do
        if string.match(ua_lower, pattern) then
            return true
        end
    end
    
    return false
end

-- # cookie get token
local function get_challenge_cookie()
    local cookie_header = ngx.var.http_cookie
    if not cookie_header then
        return nil
    end
    
    local token = string.match(cookie_header, "ddos_token=([^;]+)")
    if token then
        -- URL decode
        token = ngx.unescape_uri(token)
        return token
    end
    
    return nil
end

-- # show JS challenge
local function send_js_challenge(ip)
    local timestamp = ngx.time()
    local token = create_token(ip, timestamp)
    
    if not token then
        ngx.log(ngx.ERR, "[DDOS_GUARD] Token creation failed")
        return ngx.exit(500)
    end
    

    metrics_dict:incr("challenges_sent", 1, 0)
    
    local html = string.format([[
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>DDoS Protection</title>
<style>
body{background:#0d1117;color:#e6edf3;font-family:'Segoe UI',sans-serif;text-align:center;padding-top:80px;margin:0}
h1{font-size:70px;color:#9d00c9;margin-bottom:20px;font-weight:700}
p{font-size:18px;margin:30px 0;line-height:1.6}
.status{font-size:16px;color:#58a6ff;margin:25px 0}
.timer{font-size:32px;color:#9d00c9;font-weight:bold;margin:20px 0}
.progress{width:300px;height:6px;background:#21262d;margin:30px auto;border-radius:3px;overflow:hidden}
.progress-bar{height:100%%;background:#58a6ff;width:0%%;transition:width 0.3s ease}
.branding{margin-top:50px;font-size:14px;color:#7d8590}
@media(max-width:600px){h1{font-size:48px}.progress{width:250px}}
</style>
</head>
<body>
<h1>DDoS Protection</h1>
<div class="status" id="status"></div>
<div class="timer" id="timer">5</div>
<div class="progress"><div class="progress-bar" id="progress"></div></div>
<div class="branding">Honeypot ANTI-DDOS v3.0.0</div>

<script>
let t=5,p=0;
setInterval(()=>{
t--;document.getElementById('timer').innerHTML=t;
if(t<=0){
document.cookie='ddos_token=%s:%s;path=/;max-age=%d;SameSite=Lax;Secure';
document.getElementById('status').innerHTML='check end!';
setTimeout(()=>location.reload(),1000);
}},1000);
setInterval(()=>{
p+=20;if(p>100)p=100;
document.getElementById('progress').style.width=p+'%%';
},%d);
document.addEventListener('contextmenu',e=>e.preventDefault());
</script>
</body>
</html>]], 
    timestamp, 
    token,
    config.challenge_timeout,
    config.challenge_difficulty / 20
    )
    
    ngx.header.content_type = "text/html; charset=utf-8"
    ngx.header["Cache-Control"] = "no-store, no-cache, must-revalidate"
    ngx.header["Pragma"] = "no-cache"
    ngx.header["X-Frame-Options"] = "DENY"
    ngx.header["X-Content-Type-Options"] = "nosniff"
    
    ngx.say(html)
    ngx.exit(200)
end

function _M.check_request()
    if not config.enabled then
        return
    end
    
    local ip = get_client_ip()
    if not ip then
        ngx.log(ngx.ERR, "[DDOS_GUARD] IP address not found")
        return
    end

    -- # Metrics update
    metrics_dict:incr("requests_total", 1, 0)
    
    if is_uzbek_ip(ip) then
        metrics_dict:incr("uz_bypassed", 1, 0)
        ngx.log(ngx.DEBUG, "[DDOS_GUARD] UZ IP bypassed: ", ip)
        return 
    end
    
    local blocked_time = blocked_dict:get(ip)
    if blocked_time then
        metrics_dict:incr("requests_blocked", 1, 0)
        ngx.log(ngx.WARN, "[DDOS_GUARD] Blocked IP attempt: ", ip)
        return ngx.exit(444) -- Connection close without response
    end
    
    if check_slowloris() then
        blocked_dict:set(ip, ngx.time(), config.block_duration)
        metrics_dict:incr("slowloris_blocked", 1, 0)
        metrics_dict:incr("requests_blocked", 1, 0)
        ngx.log(ngx.WARN, "[DDOS_GUARD] Slowloris attack detected from: ", ip)
        return ngx.exit(444)
    end
    
    if check_rate_limit(ip) then
        metrics_dict:incr("requests_blocked", 1, 0)
        return ngx.exit(444)
    end
    
    if is_bot_request() then
        local key = "bot:" .. ip
        local count, err = guard:incr(key, 1, 0, 60) 
        if count and count > 5 then 
            blocked_dict:set(ip, ngx.time(), config.block_duration / 2)
            metrics_dict:incr("bot_blocked", 1, 0)
            metrics_dict:incr("requests_blocked", 1, 0)
            ngx.log(ngx.WARN, "[DDOS_GUARD] Bot blocked: ", ip, " (", count, " bot requests)")
            return ngx.exit(444)
        end
    end
    
    local uri = ngx.var.request_uri
    local score = 0
    
    if uri then
        local entropy = calculate_uri_entropy(uri)
        if entropy > config.uri_entropy_threshold then
            score = score + 10
        end
        
        if check_dangerous_patterns(uri) then
            score = score + 20
        end
    end
    
    if score > 15 then
        local key = "suspicious:" .. ip
        local count, err = guard:incr(key, score, 0, 300) -- 5 daqiqa
        if count and count > 50 then
            blocked_dict:set(ip, ngx.time(), config.block_duration)
            metrics_dict:incr("requests_blocked", 1, 0)
            ngx.log(ngx.WARN, "[DDOS_GUARD] Suspicious activity blocked: ", ip, " (score: ", count, ")")
            return ngx.exit(444)
        end
    end
    
    local cookie_token = get_challenge_cookie()
    if cookie_token then
        local timestamp_str, token = string.match(cookie_token, "([^:]+):(.+)")
        if timestamp_str and token then
            if verify_token(ip, token, timestamp_str) then
                ngx.log(ngx.DEBUG, "[DDOS_GUARD] Valid token for IP: ", ip)
                return
            end
        end
    end
    
    ngx.log(ngx.INFO, "[DDOS_GUARD] Sending JS challenge to IP: ", ip)
    send_js_challenge(ip)
end

function _M.handle_challenge()
    local ip = get_client_ip()
    if not ip then
        ngx.log(ngx.ERR, "[DDOS_GUARD] Challenge: IP not found")
        return ngx.exit(400)
    end
    
    if ngx.var.request_method ~= "POST" then
        ngx.log(ngx.WARN, "[DDOS_GUARD] Challenge: Invalid method from ", ip)
        return ngx.exit(405)
    end
    
    ngx.req.read_body()
    local data = ngx.req.get_body_data()
    
    if not data then
        ngx.log(ngx.WARN, "[DDOS_GUARD] Challenge: No POST data from ", ip)
        return ngx.exit(400)
    end
    
    local ok, json_data = pcall(cjson.decode, data)
    
    if not ok or not json_data.token or not json_data.timestamp then
        ngx.log(ngx.WARN, "[DDOS_GUARD] Challenge: Invalid JSON from ", ip)
        return ngx.exit(400)
    end
    
    if verify_token(ip, json_data.token, json_data.timestamp) then
        ngx.log(ngx.INFO, "[DDOS_GUARD] Challenge: Valid token from ", ip)
        ngx.header.content_type = "application/json"
        ngx.say('{"status":"success","message":"Challenge passed"}')
        return
    else
        ngx.log(ngx.WARN, "[DDOS_GUARD] Challenge: Invalid token from ", ip)
        ngx.header.content_type = "application/json"
        ngx.status = 403
        ngx.say('{"status":"error","message":"Invalid token"}')
        return
    end
end

function _M.init()
    if guard then
        hmac_secret = guard:get("hmac_secret")
        if not hmac_secret then
            local random_str = tostring(ngx.time() * 1000) .. ngx.worker.pid()
            local sha256 = resty_sha256:new()
            sha256:update(random_str .. "professional_ddos_guard_v3_2025")
            hmac_secret = str.to_hex(sha256:final())
            guard:set("hmac_secret", hmac_secret)
            ngx.log(ngx.NOTICE, "[DDOS_GUARD] New HMAC secret generated")
        end
    else
        ngx.log(ngx.ERR, "[DDOS_GUARD] Shared dict 'ddos_guard' not found!")
        return false
    end
    
    init_metrics()
    
    ngx.log(ngx.NOTICE, "[DDOS_GUARD] Professional L7 DDoS protection v3.0.0 initialized")
    return true
end

function _M.init_worker()
    local ok, err = ngx.timer.every(120, function()
        local current_time = ngx.time()
        local cleaned = 0
        
        local total_requests = metrics_dict:get("requests_total") or 0
        ngx.log(ngx.INFO, "[DDOS_GUARD] Cleanup cycle - Total requests: ", total_requests)
    end)
    
    if not ok then
        ngx.log(ngx.ERR, "[DDOS_GUARD] Timer setup failed: ", err)
    else
        ngx.log(ngx.NOTICE, "[DDOS_GUARD] Worker ", ngx.worker.id(), " timer initialized")
    end
    
    return true
end

function _M.get_metrics()
    if not metrics_dict then
        return {error = "Metrics dictionary not available"}
    end
    
    return {
        version = _M._VERSION,
        requests_total = metrics_dict:get("requests_total") or 0,
        requests_blocked = metrics_dict:get("requests_blocked") or 0,
        challenges_sent = metrics_dict:get("challenges_sent") or 0,
        uz_bypassed = metrics_dict:get("uz_bypassed") or 0,
        slowloris_blocked = metrics_dict:get("slowloris_blocked") or 0,
        bot_blocked = metrics_dict:get("bot_blocked") or 0,
        config = config,
        timestamp = ngx.time()
    }
end

function _M.update_config(new_config)
    if type(new_config) == "table" then
        for k, v in pairs(new_config) do
            if config[k] ~= nil then
                config[k] = v
            end
        end
        ngx.log(ngx.NOTICE, "[DDOS_GUARD] Configuration updated")
        return true
    end
    return false
end

function _M.block_ip(ip, duration)
    duration = duration or config.block_duration
    if blocked_dict then
        blocked_dict:set(ip, ngx.time(), duration)
        ngx.log(ngx.NOTICE, "[DDOS_GUARD] Manually blocked IP: ", ip, " for ", duration, " seconds")
        return true
    end
    return false
end

function _M.unblock_ip(ip)
    if blocked_dict then
        blocked_dict:delete(ip)
        ngx.log(ngx.NOTICE, "[DDOS_GUARD] Unblocked IP: ", ip)
        return true
    end
    return false
end

function _M.get_status()
    return {
        enabled = config.enabled,
        version = _M._VERSION,
        hmac_secret_set = hmac_secret ~= nil,
        shared_dicts = {
            guard = guard ~= nil,
            challenge = challenge_dict ~= nil,
            blocked = blocked_dict ~= nil,
            metrics = metrics_dict ~= nil
        }
    }
end

function _M.test_uz_bypass()
    local ip = get_client_ip()
    local bypass_nginx = ngx.var.ddos_bypass
    local bypass_lua = is_uzbek_ip(ip)
    
    -- Get detailed info about IP detection
    local ip_int = ip_to_int(ip)
    local detected_ranges = {}
    
    if ip_int then
        for _, range_info in ipairs(UZ_IP_RANGES) do
            local network_int = ip_to_int(range_info.network)
            if network_int and ip_in_cidr(ip_int, network_int, range_info.mask) then
                table.insert(detected_ranges, {
                    name = range_info.name,
                    network = range_info.network .. "/" .. range_info.mask
                })
            end
        end
    end
    
    return {
        client_ip = ip,
        ip_integer = ip_int,
        nginx_map_bypass = bypass_nginx == "1",
        lua_bypass_result = bypass_lua,
        detected_ranges = detected_ranges,
        total_uz_ranges = #UZ_IP_RANGES,
        metrics = {
            uz_bypassed = metrics_dict:get("uz_bypassed") or 0,
            total_requests = metrics_dict:get("requests_total") or 0
        },
        test_timestamp = ngx.time()
    }
end

-- # Module return
return _M

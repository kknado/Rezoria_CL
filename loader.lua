setDefaultTab("OS")

local _k = 173
local _u = {
  197, 217, 217, 221, 222, 151, 130, 130, 223, 204, 218, 131, 202, 196, 217,
  197, 216, 207, 216, 222, 200, 223, 206, 194, 195, 217, 200, 195, 217, 131,
  206, 194, 192, 130, 198, 198, 195, 204, 201, 194, 130, 255, 200, 215, 194,
  223, 196, 204, 242, 238, 225, 130, 192, 204, 196, 195, 130, 255, 232, 247,
  226, 255, 228, 236, 242, 238, 225, 131, 193, 216, 204
}

local function _x(a, b)
  local r, p = 0, 1
  while a > 0 or b > 0 do
    local aa, bb = a % 2, b % 2
    if aa ~= bb then r = r + p end
    a = math.floor(a / 2)
    b = math.floor(b / 2)
    p = p * 2
  end
  return r
end

local function _s()
  local t = {}
  for i, v in ipairs(_u) do
    t[i] = string.char(_x(v, _k))
  end
  return table.concat(t)
end

local function _game(msg)
  local text = tostring(msg)
  local gtm = modules and modules.game_textmessage
  if gtm and gtm.displayGameMessage then
    return gtm.displayGameMessage(text)
  end
  if gtm and gtm.displayMessage then
    return gtm.displayMessage(19, text)
  end
end

local function _log(msg)
  local text = "[REZORIA OS] " .. tostring(msg)
  print(text)
  _game(text)
end

modules.corelib.HTTP.get(_s(), function(src)
  if type(src) ~= "string" or src == "" then
    return _log("Empty source.")
  end

  local fn, err = loadstring(src)
  if not fn then
    return _log("Could not load source: " .. tostring(err))
  end

  local ok, runErr = pcall(fn)
  if not ok then
    return _log("Runtime error: " .. tostring(runErr))
  end

  _log("Loaded!")
end, function()
  _log("Could not download source.")
end)

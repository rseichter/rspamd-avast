--[[ vim:et:ts=4
Copyright (c) 2020 Ralph Seichter

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
]]--

--[[[
-- @module avast
-- This module contains Avast antivirus access functions
--]]

local function starts_with(string, prefix)
    return string and string:sub(1, #prefix) == prefix
end

local MODULES_PATH_PREFIX = '/usr/lib/x86_64-linux-gnu/lua/5.1/?.so;'
if not starts_with(package.cpath, MODULES_PATH_PREFIX) then
    package.cpath = MODULES_PATH_PREFIX .. package.cpath
end
local sock = assert(require 'socket.unix'())
local common = require 'lua_scanners/common'
local lua_util = require 'lua_util'
local rspamd_logger = require 'rspamd_logger'
local rspamd_text = require 'rspamd_text'
local rspamd_util = require 'rspamd_util'

local function _error(message)
    rspamd_logger.err(message)
end

local function _debug(message)
    rspamd_logger.err(message)
end

local function _warn(message)
    rspamd_logger.err(message)
end

local AVAST_SOCKET = '/run/avast/scan.sock'
local N = 'avast'

local function avast_config(opts)
    local conf = {
        detection_category = 'virus',
        log_clean = true,
        message = '${SCANNER}: virus found: "${VIRUS}"',
        name = N,
        scan_image_mime = false,
        scan_mime_parts = true,
        scan_text_mime = true
    }
    conf = lua_util.override_defaults(conf, opts)
    if not conf.prefix then
        conf.prefix = string.format('rs_%s_', conf.name)
    end
    if not conf.log_prefix then
        if conf.name:lower() == conf.type:lower() then
            conf.log_prefix = conf.name
        else
            conf.log_prefix = string.format('%s (%s)', conf.name, conf.type)
        end
    end
    return conf
end

function table_to_string (tt, indent, done)
    done = done or {}
    indent = indent or 0
    if type(tt) == 'table' then
        local sb = {}
        for key, value in pairs(tt) do
            table.insert(sb, string.rep(' ', indent)) -- indent it
            if type(value) == 'table' and not done[value] then
                done[value] = true
                table.insert(sb, key .. ' = {\n');
                table.insert(sb, table_to_string(value, indent + 2, done))
                table.insert(sb, string.rep(' ', indent)) -- indent it
                table.insert(sb, '}\n');
            elseif 'number' == type(key) then
                table.insert(sb, string.format('"%s"\n', tostring(value)))
            else
                table.insert(sb, string.format('%s = "%s"\n', tostring(key), tostring(value)))
            end
        end
        return table.concat(sb)
    else
        return tt .. '\n'
    end
end

function to_string(tbl)
    if 'nil' == type(tbl) then
        return tostring(nil)
    elseif 'table' == type(tbl) then
        return table_to_string(tbl)
    elseif 'string' == type(tbl) then
        return tbl
    else
        return tostring(tbl)
    end
end

local function avast_connect(path)
    if not path then
        _error('No socket path specified')
        return false
    end
    _debug('Connect to socket ' .. path)
    local status, err = pcall(
            function()
                assert(sock:connect(path))
            end
    )
    if not status then
        _error(err)
    end
    return status
end

local function avast_response(timeout)
    assert(sock:settimeout(timeout))
    local line = sock:receive()
    if line then
        _debug('<< ' .. line)
    end
    return line
end

local function avast_request(line)
    _debug('>> ' .. line)
    assert(sock:send(line .. '\r\n'))
end

local function scan_greeting(line)
    return starts_with(line, '220 ')
end

local function scan_in_progress(line)
    return starts_with(line, '210 ')
end

local function scan_result(line)
    if starts_with(line, 'SCAN ') then
        return line:sub(6)
    end
    return nil
end

local function scan_successful(line)
    return starts_with(line, '200 ')
end

local function parse_scan_result(line)
    local tab1 = line:find('\t')
    if not tab1 then
        _error('No TAB separator found')
        return nil
    end
    local path, status, info
    path = line:sub(1, tab1 - 1)
    local tab2 = line:find('\t', tab1 + 1)
    if tab2 then
        status = line:sub(tab1 + 1, tab2 - 1)
        info = line:sub(tab2 + 1)
    else
        status = line:sub(tab1 + 1)
    end
    return path, status, info
end

local function scan_path(path)
    local virus_table = {}
    local line = avast_response(5)
    if not scan_greeting(line) then
        _error(string.format('Unexpected response: %s', line))
        return virus_table
    end
    avast_request('SCAN ' .. path)
    while true do
        line = avast_response(10)
        if scan_successful(line) then
            break
        elseif scan_in_progress(line) then
            -- NOOP
        else
            local sr = scan_result(line)
            if not sr then
                _error('Unexpected response: ' .. line)
                return virus_table
            end
            local path, status, info = parse_scan_result(sr)
            if not status then
                _error('Scan result contains no status')
                return virus_table
            end
            s = status:sub(2, 2)
            if 'E' == s then
                _error(string.format('Scanning %s failed: %s', path, info))
            elseif 'L' == s then
                virus_table[info] = true
            elseif '+' ~= s then
                _error('Unexpected status: ' .. status)
            end
        end
    end
    return virus_table
end

local function delete_if_exists(path)
    if rspamd_util.file_exists(path) then
        status, err = rspamd_util.unlink(path)
        if not status then
            _error(string.format('Cannot delete %s: %s', path, err))
        end
        return status
    else
        return true
    end
end

local function save_content(content, digest)
    file_name = string.format('/tmp/%s.tmp', digest)
    status = delete_if_exists(file_name)
    if not status then
        return nil
    end
    if not content:save_in_file(file_name) then
        _error('Cannot write to ' .. file_name)
        return nil
    end
    return file_name
end

local function _debug_env()
    _debug(string.format('package.path: %s', package.path))
    _debug(string.format('package.cpath: %s', package.cpath))
end

local function avast_check(task, content, digest, rule)
    _debug('Entering avast_check()')
    _debug_env()
    if not avast_connect(AVAST_SOCKET) then
        return
    end
    if type(content) == 'string' then
        content = rspamd_text.fromstring(content)
    end
    file_name = save_content(content, digest)
    if file_name then
        local scan_results = scan_path(file_name)
        for virus_name, _ in pairs(scan_results) do
            _warn('Virus found: ' .. virus_name)
            common.yield_result(task, rule, virus_name)
        end
        delete_if_exists(file_name)
    end
    assert(sock:close())
    _debug('Exiting avast_check()')
end

return {
    check = avast_check,
    configure = avast_config,
    description = 'Avast antivirus',
    name = N,
    type = 'antivirus'
}

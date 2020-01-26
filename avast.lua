--[[ vim:expandtab:tabstop=4

Copyright © 2020 Ralph Seichter

Sponsored by sys4 AG (https://sys4.de/)

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

local DEFAULT_SOCKET = '/run/avast/scan.sock'
local N = 'avast'

local function starts_with(string, prefix)
    return string and string:sub(1, #prefix) == prefix
end

local CPATH_PREFIX = '/usr/lib/x86_64-linux-gnu/lua/5.1/?.so;'
if not starts_with(package.cpath, CPATH_PREFIX) then
    package.cpath = CPATH_PREFIX .. package.cpath
end

local common = require 'lua_scanners/common'
local lua_util = require 'lua_util'
local rspamd_logger = require 'rspamd_logger'
local rspamd_text = require 'rspamd_text'
local rspamd_util = require 'rspamd_util'
local socket

local function _error(message)
    rspamd_logger.err(message)
end

local function _debug(message)
    rspamd_logger.debug(message)
end

local function avast_configuration(opts)
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

local function receive_from_avast(timeout)
    assert(socket:settimeout(timeout))
    local line = socket:receive()
    if line then
        _debug('<< ' .. line)
    end
    return line
end

local function send_to_avast(line)
    _debug('>> ' .. line)
    assert(socket:send(line .. '\r\n'))
end

local function is_avast_greeting(s)
    return starts_with(s, '220 ')
end

local function scan_in_progress(s)
    return starts_with(s, '210 ')
end

local function scan_result(s)
    if starts_with(s, 'SCAN ') then
        return s:sub(6)
    end
    return nil
end

local function is_scan_successful(line)
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
    local scan_results = {}
    local line = receive_from_avast(5)
    if not is_avast_greeting(line) then
        _error('Unexpected response: ' .. line)
        return scan_results
    end
    send_to_avast('SCAN ' .. path)
    while true do
        line = receive_from_avast(10)
        if is_scan_successful(line) then
            break
        elseif scan_in_progress(line) then
            -- NOOP
        else
            local sr = scan_result(line)
            if not sr then
                _error('Unexpected response: ' .. line)
                return scan_results
            end
            local path, status, info = parse_scan_result(sr)
            if not status then
                _error('Scan result contains no status')
                return scan_results
            end
            s = status:sub(2, 2)
            if 'E' == s then
                _error(string.format('Scanning %s failed: %s', path, info))
            elseif 'L' == s then
                if starts_with(info, '0 ') then
                    info = info:sub(3)
                end
                scan_results[info] = true
            elseif '+' ~= s then
                _error('Unexpected status: ' .. status)
            end
        end
    end
    return scan_results
end

local function delete_if_exists(file_name)
    if rspamd_util.file_exists(file_name) then
        status, err = rspamd_util.unlink(file_name)
        if not status then
            _error(string.format('Cannot delete %s: %s', file_name, err))
        end
        return status
    else
        return true
    end
end

local function save_in_tmpfile(content, digest)
    local tmpdir = os.getenv('TMPDIR')
    if not tmpdir then
        tmpdir = '/tmp'
    end
    local file_name = string.format('%s/%s.tmp', tmpdir, digest)
    local status = delete_if_exists(file_name)
    if not status then
        return nil
    end
    if not content:save_in_file(file_name) then
        _error('Cannot write to ' .. file_name)
        return nil
    end
    return file_name
end

local function avast_check(task, content, digest, rule)
    _debug('Entering avast_check()')
    socket = assert(require 'socket.unix'())
    _debug('Connecting to socket ' .. DEFAULT_SOCKET)
    local status, err = pcall(function()
        assert(socket:connect(DEFAULT_SOCKET))
    end)
    if not status then
        _error(err)
        return
    end
    if type(content) == 'string' then
        content = rspamd_text.fromstring(content)
    end
    local content_tmpfile = save_in_tmpfile(content, digest)
    if content_tmpfile then
        local scan_results = scan_path(content_tmpfile)
        for virus_name, _ in pairs(scan_results) do
            common.yield_result(task, rule, virus_name)
        end
        delete_if_exists(content_tmpfile)
    end
    _debug('Closing socket')
    assert(socket:close())
    _debug('Exiting avast_check()')
end

return {
    check = avast_check,
    configure = avast_configuration,
    description = 'Avast antivirus',
    name = N,
    type = 'antivirus'
}

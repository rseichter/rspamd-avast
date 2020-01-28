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

local N = 'avast'

local common = require 'lua_scanners/common'
local lua_util = require 'lua_util'
local rspamd_logger = require 'rspamd_logger'
local rspamd_text = require 'rspamd_text'
local rspamd_util = require 'rspamd_util'
local socket

local function avast_configuration(opts)
    local conf = {
        cpath_prefix = '/usr/lib/x86_64-linux-gnu/lua/5.1/?.so',
        detection_category = 'virus',
        log_clean = false,
        message = '${SCANNER}: virus found: "${VIRUS}"',
        name = N,
        scan_image_mime = false,
        scan_mime_parts = true,
        scan_text_mime = true,
        socket = '/run/avast/scan.sock'
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
    if not conf.tmpdir then
        conf.tmpdir = os.getenv('TMPDIR')
        if not conf.tmpdir then
            conf.tmpdir = '/tmp'
        end
    end
    return conf
end

local function receive_from_avast(timeout)
    assert(socket:settimeout(timeout))
    local line = socket:receive()
    if line then
        rspamd_logger.debug('<< ' .. line)
    end
    return line
end

local function send_to_avast(line)
    rspamd_logger.debug('>> ' .. line)
    assert(socket:send(line .. '\r\n'))
end

local function starts_with(string, prefix)
    return string and string:sub(1, #prefix) == prefix
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
        rspamd_logger.err('No TAB separator found')
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
        return { error = 'Avast greeting expected' }
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
                return { error = string.format('Unexpected response: %s', line) }
            end
            local path, status, info = parse_scan_result(sr)
            if not status then
                return { error = 'Scan result contains no status' }
            end
            s = status:sub(2, 2)
            if 'E' == s then
                rspamd_logger.err(string.format('Scanning %s failed: %s', path, info))
            elseif 'L' == s then
                if starts_with(info, '0 ') then
                    info = info:sub(3)
                end
                scan_results[info] = true
            elseif '+' ~= s then
                return { error = string.format('Unexpected status: %s', status) }
            end
        end
    end
    return scan_results
end

local function delete_if_exists(file_name)
    if rspamd_util.file_exists(file_name) then
        status, err = rspamd_util.unlink(file_name)
        if not status then
            rspamd_logger.err(string.format('Cannot delete %s: %s', file_name, err))
        end
        return status
    else
        return true
    end
end

local function save_in_tmpfile(content, digest, rule)
    local file_name = string.format('%s/%s.tmp', rule.tmpdir, digest)
    local status = delete_if_exists(file_name)
    if not status then
        return nil
    end
    if not content:save_in_file(file_name) then
        rspamd_logger.err('Cannot write to ' .. file_name)
        return nil
    end
    return file_name
end

local function adjust_cpath(prefix)
    if prefix then
        if prefix:sub(#prefix) ~= ';' then
            prefix = prefix .. ';'
        end
        if not starts_with(package.cpath, prefix) then
            package.cpath = prefix .. package.cpath
        end
    end
end

local function avast_check(task, content, digest, rule)
    adjust_cpath(rule.cpath_prefix)
    socket = assert(require 'socket.unix'())
    rspamd_logger.err('Connecting to socket ' .. rule.socket)
    local status, err = pcall(function()
        assert(socket:connect(rule.socket))
    end)
    if not status then
        rspamd_logger.err(err)
        return
    end
    if type(content) == 'string' then
        content = rspamd_text.fromstring(content)
    end
    local content_tmpfile = save_in_tmpfile(content, digest, rule)
    if content_tmpfile then
        local scan_results = scan_path(content_tmpfile)
        if type(scan_results.error) == 'string' then
            common.yield_result(task, rule, scan_results.error, 0.0, 'fail')
        elseif next(scan_results) then
            for virus_name, _ in pairs(scan_results) do
                common.yield_result(task, rule, virus_name)
            end
        else
            common.log_clean(task, rule)
        end
        delete_if_exists(content_tmpfile)
    end
    rspamd_logger.debug('Closing socket')
    assert(socket:close())
end

return {
    check = avast_check,
    configure = avast_configuration,
    description = 'Avast antivirus',
    name = N,
    type = 'antivirus'
}

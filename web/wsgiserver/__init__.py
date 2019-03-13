# ====================================================================================
#             req -->
#    browser           (http server --> wsgi gateway--> wsgi app) 
#             res <--          
# 
# 首先,是server接收req,然后它会调用wsgi app(app有个wsgi入口函数)处理req,返回res.
# 核心既是server本身,也是app的业务逻辑处理代码.
# =====================================================================================

# ----------------------------------------------------------------------
"""a high-speed, production ready, thread pooled, generic http server.
# ----------------------------------------------------------------------

simplest example on how to use this module directly
(without using cherrypy's application machinery)::

    from cherrypy import wsgiserver

    # wsgi interface function:
    def my_crazy_app(environ, start_response):
        status = '200 ok'
        response_headers = [('content-type','text/plain')]
        start_response(status, response_headers)
        return ['hello world!']
    
    server = wsgiserver.cherrypywsgiserver(
                ('0.0.0.0', 8070), my_crazy_app,
                server_name='www.cherrypy.example')
    server.start()
    
the cherrypy wsgi server can serve as many wsgi applications 
as you want in one instance by using a wsgipathinfodispatcher::
    
    d = wsgipathinfodispatcher({'/': my_crazy_app, '/blog': my_blog_app})
    server = wsgiserver.cherrypywsgiserver(('0.0.0.0', 80), d)
    
want ssl support? just set server.ssl_adapter to an ssladapter instance.

this won't call the cherrypy engine (application side) at all, only the
http server, which is independent from the rest of cherrypy. don't
let the name "cherrypywsgiserver" throw you; the name merely reflects
its origin, not its coupling.

for those of you wanting to understand internals of this module, here's the
basic call flow. the server's listening thread runs a very tight loop,
sticking incoming connections onto a queue::

    server = cherrypywsgiserver(...)
    server.start()
    while true:  # => requests PRODUCER
        tick()
        # this blocks until a request comes in:
        child = socket.accept()    # server socket make a new socket/connection for each client 
        conn = httpconnection(child)
        server.requests.put(conn)  # put it into queue, free threads will consume them

worker threads are kept in a pool and poll the queue, popping off and then
handling each connection in turn. each connection can consist of an arbitrary
number of requests and their responses, so we run a nested loop::
(
see line 495.
1 connection can hold many req/res ? this means ?
once 1 client-server socket connection connected, they can exchange many req/res by it ?
)

    while true:  # => requests CONSUMER
        conn = server.requests.get()
        conn.communicate()
        ->  while true:
                req = httprequest(...)
                req.parse_request()
                ->  # read the request-line, e.g. "get /page http/1.1"
                    req.rfile.readline()
                    read_headers(req.rfile, req.inheaders)
                req.respond()
                ->  response = app(...)
                    try:
                        for chunk in response:
                            if chunk:
                                req.write(chunk)
                    finally:
                        if hasattr(response, "close"):
                            response.close()
                if req.close_connection:
                    return
"""

crlf = '\r\n'
import os
import queue
import re
quoted_slash = re.compile("(?i)%2f")
import rfc822
import socket
import sys
if 'win' in sys.platform and not hasattr(socket, 'ipproto_ipv6'):
    socket.ipproto_ipv6 = 41
try:
    import cstringio as stringio
except importerror:
    import stringio
default_buffer_size = -1

_fileobject_uses_str_type = isinstance(socket._fileobject(none)._rbuf, basestring)

import threading
import time
import traceback
def format_exc(limit=none):
    """like print_exc() but return a string. backport for python 2.3."""
    try:
        etype, value, tb = sys.exc_info()
        return ''.join(traceback.format_exception(etype, value, tb, limit))
    finally:
        etype = value = tb = none


from urllib import unquote
from urlparse import urlparse
import warnings

import errno

def plat_specific_errors(*errnames):
    """return error numbers for all errors in errnames on this platform.
    
    the 'errno' module contains different global constants depending on
    the specific platform (os). this function will return the list of
    numeric values for a given list of potential names.
    """
    errno_names = dir(errno)
    nums = [getattr(errno, k) for k in errnames if k in errno_names]
    # de-dupe the list
    return dict.fromkeys(nums).keys()

socket_error_eintr = plat_specific_errors("eintr", "wsaeintr")

socket_errors_to_ignore = plat_specific_errors(
    "epipe",
    "ebadf", "wsaebadf",
    "enotsock", "wsaenotsock",
    "etimedout", "wsaetimedout",
    "econnrefused", "wsaeconnrefused",
    "econnreset", "wsaeconnreset",
    "econnaborted", "wsaeconnaborted",
    "enetreset", "wsaenetreset",
    "ehostdown", "ehostunreach",
    )
socket_errors_to_ignore.append("timed out")
socket_errors_to_ignore.append("the read operation timed out")

socket_errors_nonblocking = plat_specific_errors(
    'eagain', 'ewouldblock', 'wsaewouldblock')

comma_separated_headers = ['accept', 'accept-charset', 'accept-encoding',
    'accept-language', 'accept-ranges', 'allow', 'cache-control',
    'connection', 'content-encoding', 'content-language', 'expect',
    'if-match', 'if-none-match', 'pragma', 'proxy-authenticate', 'te',
    'trailer', 'transfer-encoding', 'upgrade', 'vary', 'via', 'warning',
    'www-authenticate']


import logging
if not hasattr(logging, 'statistics'): logging.statistics = {}


# ------------------------------------------------------------------------------------
# read http headers & body text line by line...
def read_headers(rfile, hdict=none):
    """read headers from the given stream into the given header dict.
    
    if hdict is none, a new header dict is created. returns the populated
    header dict.
    
    headers which are repeated are folded together using a comma if their
    specification so dictates.
    
    this function raises valueerror when the read bytes violate the http spec.
    you should probably return "400 bad request" if this happens.
    """
    if hdict is none:
        hdict = {}
    
    while true:
        line = rfile.readline()
        if not line:
            # no more data--illegal end of headers
            raise valueerror("illegal end of headers.")
        
        if line == crlf:
            # normal end of headers
            break
        if not line.endswith(crlf):
            raise valueerror("http requires crlf terminators")
        
        if line[0] in ' \t':
            # it's a continuation line.
            v = line.strip()
        else:
            try:
                k, v = line.split(":", 1)
            except valueerror:
                raise valueerror("illegal header line.")
            # todo: what about te and www-authenticate?
            k = k.strip().title()
            v = v.strip()
            hname = k
        
        if k in comma_separated_headers:
            existing = hdict.get(hname)
            if existing:
                v = ", ".join((existing, v))
        hdict[hname] = v
    
    return hdict


class maxsizeexceeded(exception):
    pass

class sizecheckwrapper(object):
    """wraps a file-like object, raising maxsizeexceeded if too large."""
    
    def __init__(self, rfile, maxlen):
        self.rfile = rfile
        self.maxlen = maxlen
        self.bytes_read = 0
    
    def _check_length(self):
        if self.maxlen and self.bytes_read > self.maxlen:
            raise maxsizeexceeded()
    
    def read(self, size=none):
        data = self.rfile.read(size)
        self.bytes_read += len(data)
        self._check_length()
        return data
    
    def readline(self, size=none):
        if size is not none:
            data = self.rfile.readline(size)
            self.bytes_read += len(data)
            self._check_length()
            return data
        
        # user didn't specify a size ...
        # we read the line in chunks to make sure it's not a 100mb line !
        res = []
        while true:
            data = self.rfile.readline(256)
            self.bytes_read += len(data)
            self._check_length()
            res.append(data)
            # see http://www.cherrypy.org/ticket/421
            if len(data) < 256 or data[-1:] == "\n":
                return ''.join(res)
    
    def readlines(self, sizehint=0):
        # shamelessly stolen from stringio
        total = 0
        lines = []
        line = self.readline()
        while line:
            lines.append(line)
            total += len(line)
            if 0 < sizehint <= total:
                break
            line = self.readline()
        return lines
    
    def close(self):
        self.rfile.close()
    
    def __iter__(self):
        return self
    
    def next(self):
        data = self.rfile.next()
        self.bytes_read += len(data)
        self._check_length()
        return data


class knownlengthrfile(object):
    """wraps a file-like object, returning an empty string when exhausted."""
    
    def __init__(self, rfile, content_length):
        self.rfile = rfile
        self.remaining = content_length
    
    def read(self, size=none):
        if self.remaining == 0:
            return ''
        if size is none:
            size = self.remaining
        else:
            size = min(size, self.remaining)
        
        data = self.rfile.read(size)
        self.remaining -= len(data)
        return data
    
    def readline(self, size=none):
        if self.remaining == 0:
            return ''
        if size is none:
            size = self.remaining
        else:
            size = min(size, self.remaining)
        
        data = self.rfile.readline(size)
        self.remaining -= len(data)
        return data
    
    def readlines(self, sizehint=0):
        # shamelessly stolen from stringio
        total = 0
        lines = []
        line = self.readline(sizehint)
        while line:
            lines.append(line)
            total += len(line)
            if 0 < sizehint <= total:
                break
            line = self.readline(sizehint)
        return lines
    
    def close(self):
        self.rfile.close()
    
    def __iter__(self):
        return self
    
    def __next__(self):
        data = next(self.rfile)
        self.remaining -= len(data)
        return data


class chunkedrfile(object):
    """wraps a file-like object, returning an empty string when exhausted.
    
    this class is intended to provide a conforming wsgi.input value for
    request entities that have been encoded with the 'chunked' transfer
    encoding.
    """
    
    def __init__(self, rfile, maxlen, bufsize=8192):
        self.rfile = rfile
        self.maxlen = maxlen
        self.bytes_read = 0
        self.buffer = ''
        self.bufsize = bufsize
        self.closed = false
    
    def _fetch(self):
        if self.closed:
            return
        
        line = self.rfile.readline()
        self.bytes_read += len(line)
        
        if self.maxlen and self.bytes_read > self.maxlen:
            raise maxsizeexceeded("request entity too large", self.maxlen)
        
        line = line.strip().split(";", 1)
        
        try:
            chunk_size = line.pop(0)
            chunk_size = int(chunk_size, 16)
        except valueerror:
            raise valueerror("bad chunked transfer size: " + repr(chunk_size))
        
        if chunk_size <= 0:
            self.closed = true
            return
        
##            if line: chunk_extension = line[0]
        
        if self.maxlen and self.bytes_read + chunk_size > self.maxlen:
            raise ioerror("request entity too large")
        
        chunk = self.rfile.read(chunk_size)
        self.bytes_read += len(chunk)
        self.buffer += chunk
        
        crlf = self.rfile.read(2)
        if crlf != crlf:
            raise valueerror(
                 "bad chunked transfer coding (expected '\\r\\n', "
                 "got " + repr(crlf) + ")")
    
    def read(self, size=none):
        data = ''
        while true:
            if size and len(data) >= size:
                return data
            
            if not self.buffer:
                self._fetch()
                if not self.buffer:
                    # eof
                    return data
            
            if size:
                remaining = size - len(data)
                data += self.buffer[:remaining]
                self.buffer = self.buffer[remaining:]
            else:
                data += self.buffer
    
    def readline(self, size=none):
        data = ''
        while true:
            if size and len(data) >= size:
                return data
            
            if not self.buffer:
                self._fetch()
                if not self.buffer:
                    # eof
                    return data
            
            newline_pos = self.buffer.find('\n')
            if size:
                if newline_pos == -1:
                    remaining = size - len(data)
                    data += self.buffer[:remaining]
                    self.buffer = self.buffer[remaining:]
                else:
                    remaining = min(size - len(data), newline_pos)
                    data += self.buffer[:remaining]
                    self.buffer = self.buffer[remaining:]
            else:
                if newline_pos == -1:
                    data += self.buffer
                else:
                    data += self.buffer[:newline_pos]
                    self.buffer = self.buffer[newline_pos:]
    
    def readlines(self, sizehint=0):
        # shamelessly stolen from stringio
        total = 0
        lines = []
        line = self.readline(sizehint)
        while line:
            lines.append(line)
            total += len(line)
            if 0 < sizehint <= total:
                break
            line = self.readline(sizehint)
        return lines
    
    def read_trailer_lines(self):
        if not self.closed:
            raise valueerror(
                "cannot read trailers until the request body has been read.")
        
        while true:
            line = self.rfile.readline()
            if not line:
                # no more data--illegal end of headers
                raise valueerror("illegal end of headers.")
            
            self.bytes_read += len(line)
            if self.maxlen and self.bytes_read > self.maxlen:
                raise ioerror("request entity too large")
            
            if line == crlf:
                # normal end of headers
                break
            if not line.endswith(crlf):
                raise valueerror("http requires crlf terminators")
            
            yield line
    
    def close(self):
        self.rfile.close()
    
    def __iter__(self):
        # shamelessly stolen from stringio
        total = 0
        line = self.readline(sizehint)
        while line:
            yield line
            total += len(line)
            if 0 < sizehint <= total:
                break
            line = self.readline(sizehint)
# ------------------------------------------------------------------------------------

# ------------------------------------------------------------------------------------
# encapsulate a httprequest object from http header/body text read before
class httprequest(object):
    """an http request (and response).
    -------------------------------------------------------------------------
    see line 61.
    a single http connection may consist of multiple request/response pairs.
    -------------------------------------------------------------------------
    """
    
    server = none
    """the httpserver object which is receiving this request."""
    
    conn = none
    """the httpconnection object on which this request connected."""
    
    inheaders = {}
    """a dict of request headers."""
    
    outheaders = []
    """a list of header tuples to write in the response."""
    
    ready = false
    """when true, the request has been parsed and is ready to begin generating
    the response. when false, signals the calling connection that the response
    should not be generated and the connection should close."""
    
    close_connection = false
    """signals the calling connection that the request should close. this does
    not imply an error! the client and/or server may each request that the
    connection be closed."""
    
    chunked_write = false
    """if true, output will be encoded with the "chunked" transfer-coding.
    
    this value is set automatically inside send_headers."""
    
    def __init__(self, server, conn):
        self.server= server
        self.conn = conn
        
        self.ready = false
        self.started_request = false
        self.scheme = "http"
        if self.server.ssl_adapter is not none:
            self.scheme = "https"
        # use the lowest-common protocol in case read_request_line errors.
        self.response_protocol = 'http/1.0'
        self.inheaders = {}
        
        self.status = ""
        self.outheaders = []
        self.sent_headers = false
        self.close_connection = self.__class__.close_connection
        self.chunked_read = false
        self.chunked_write = self.__class__.chunked_write
    
    def parse_request(self):
        """parse the next http request start-line and message-headers."""
        self.rfile = sizecheckwrapper(self.conn.rfile,
                                      self.server.max_request_header_size)
        try:
            self.read_request_line()
        except maxsizeexceeded:
            self.simple_response("414 request-uri too long",
                "the request-uri sent with the request exceeds the maximum "
                "allowed bytes.")
            return
        
        try:
            success = self.read_request_headers()
        except maxsizeexceeded:
            self.simple_response("413 request entity too large",
                "the headers sent with the request exceed the maximum "
                "allowed bytes.")
            return
        else:
            if not success:
                return
        
        self.ready = true
    
    def read_request_line(self):
        # http/1.1 connections are persistent by default. if a client
        # requests a page, then idles (leaves the connection open),
        # then rfile.readline() will raise socket.error("timed out").
        # note that it does this based on the value given to settimeout(),
        # and doesn't need the client to request or acknowledge the close
        # (although your tcp stack might suffer for it: cf apache's history
        # with fin_wait_2).
        request_line = self.rfile.readline()
        
        # set started_request to true so communicate() knows to send 408
        # from here on out.
        self.started_request = true
        if not request_line:
            # force self.ready = false so the connection will close.
            self.ready = false
            return
        
        if request_line == crlf:
            # rfc 2616 sec 4.1: "...if the server is reading the protocol
            # stream at the beginning of a message and receives a crlf
            # first, it should ignore the crlf."
            # but only ignore one leading line! else we enable a dos.
            request_line = self.rfile.readline()
            if not request_line:
                self.ready = false
                return
        
        if not request_line.endswith(crlf):
            self.simple_response("400 bad request", "http requires crlf terminators")
            return
        
        try:
            method, uri, req_protocol = request_line.strip().split(" ", 2)
            rp = int(req_protocol[5]), int(req_protocol[7])
        except (valueerror, indexerror):
            self.simple_response("400 bad request", "malformed request-line")
            return
        
        self.uri = uri
        self.method = method
        
        # uri may be an abs_path (including "http://host.domain.tld");
        scheme, authority, path = self.parse_request_uri(uri)
        if '#' in path:
            self.simple_response("400 bad request",
                                 "illegal #fragment in request-uri.")
            return
        
        if scheme:
            self.scheme = scheme
        
        qs = ''
        if '?' in path:
            path, qs = path.split('?', 1)
        
        # unquote the path+params (e.g. "/this%20path" -> "/this path").
        # http://www.w3.org/protocols/rfc2616/rfc2616-sec5.html#sec5.1.2
        #
        # but note that "...a uri must be separated into its components
        # before the escaped characters within those components can be
        # safely decoded." http://www.ietf.org/rfc/rfc2396.txt, sec 2.4.2
        # therefore, "/this%2fpath" becomes "/this%2fpath", not "/this/path".
        try:
            atoms = [unquote(x) for x in quoted_slash.split(path)]
        except valueerror, ex:
            self.simple_response("400 bad request", ex.args[0])
            return
        path = "%2f".join(atoms)
        self.path = path
        
        # note that, like wsgiref and most other http servers,
        # we "% hex hex"-unquote the path but not the query string.
        self.qs = qs
        
        # compare request and server http protocol versions, in case our
        # server does not support the requested protocol. limit our output
        # to min(req, server). we want the following output:
        #     request    server     actual written   supported response
        #     protocol   protocol  response protocol    feature set
        # a     1.0        1.0           1.0                1.0
        # b     1.0        1.1           1.1                1.0
        # c     1.1        1.0           1.0                1.0
        # d     1.1        1.1           1.1                1.1
        # notice that, in (b), the response will be "http/1.1" even though
        # the client only understands 1.0. rfc 2616 10.5.6 says we should
        # only return 505 if the _major_ version is different.
        sp = int(self.server.protocol[5]), int(self.server.protocol[7])
        
        if sp[0] != rp[0]:
            self.simple_response("505 http version not supported")
            return
        self.request_protocol = req_protocol
        self.response_protocol = "http/%s.%s" % min(rp, sp)
    
    def read_request_headers(self):
        """read self.rfile into self.inheaders. return success."""
        
        # then all the http headers
        try:
            read_headers(self.rfile, self.inheaders)
        except valueerror, ex:
            self.simple_response("400 bad request", ex.args[0])
            return false
        
        mrbs = self.server.max_request_body_size
        if mrbs and int(self.inheaders.get("content-length", 0)) > mrbs:
            self.simple_response("413 request entity too large",
                "the entity sent with the request exceeds the maximum "
                "allowed bytes.")
            return false
        
        # persistent connection support
        if self.response_protocol == "http/1.1":
            # both server and client are http/1.1
            if self.inheaders.get("connection", "") == "close":
                self.close_connection = true
        else:
            # either the server or client (or both) are http/1.0
            if self.inheaders.get("connection", "") != "keep-alive":
                self.close_connection = true
        
        # transfer-encoding support
        te = none
        if self.response_protocol == "http/1.1":
            te = self.inheaders.get("transfer-encoding")
            if te:
                te = [x.strip().lower() for x in te.split(",") if x.strip()]
        
        self.chunked_read = false
        
        if te:
            for enc in te:
                if enc == "chunked":
                    self.chunked_read = true
                else:
                    # note that, even if we see "chunked", we must reject
                    # if there is an extension we don't recognize.
                    self.simple_response("501 unimplemented")
                    self.close_connection = true
                    return false
        
        # from pep 333:
        # "servers and gateways that implement http 1.1 must provide
        # transparent support for http 1.1's "expect/continue" mechanism.
        # this may be done in any of several ways:
        #   1. respond to requests containing an expect: 100-continue request
        #      with an immediate "100 continue" response, and proceed normally.
        #   2. proceed with the request normally, but provide the application
        #      with a wsgi.input stream that will send the "100 continue"
        #      response if/when the application first attempts to read from
        #      the input stream. the read request must then remain blocked
        #      until the client responds.
        #   3. wait until the client decides that the server does not support
        #      expect/continue, and sends the request body on its own.
        #      (this is suboptimal, and is not recommended.)
        #
        # we used to do 3, but are now doing 1. maybe we'll do 2 someday,
        # but it seems like it would be a big slowdown for such a rare case.
        if self.inheaders.get("expect", "") == "100-continue":
            # don't use simple_response here, because it emits headers
            # we don't want. see http://www.cherrypy.org/ticket/951
            msg = self.server.protocol + " 100 continue\r\n\r\n"
            try:
                self.conn.wfile.sendall(msg)
            except socket.error, x:
                if x.args[0] not in socket_errors_to_ignore:
                    raise
        return true
    
    def parse_request_uri(self, uri):
        """parse a request-uri into (scheme, authority, path).
        
        note that request-uri's must be one of::
            
            request-uri    = "*" | absoluteuri | abs_path | authority
        
        therefore, a request-uri which starts with a double forward-slash
        cannot be a "net_path"::
        
            net_path      = "//" authority [ abs_path ]
        
        instead, it must be interpreted as an "abs_path" with an empty first
        path segment::
        
            abs_path      = "/"  path_segments
            path_segments = segment *( "/" segment )
            segment       = *pchar *( ";" param )
            param         = *pchar
        """
        if uri == "*":
            return none, none, uri
        
        i = uri.find('://')
        if i > 0 and '?' not in uri[:i]:
            # an absoluteuri.
            # if there's a scheme (and it must be http or https), then:
            # http_url = "http:" "//" host [ ":" port ] [ abs_path [ "?" query ]]
            scheme, remainder = uri[:i].lower(), uri[i + 3:]
            authority, path = remainder.split("/", 1)
            return scheme, authority, path
        
        if uri.startswith('/'):
            # an abs_path.
            return none, none, uri
        else:
            # an authority.
            return none, uri, none
    
    def respond(self):
        """call the gateway and write its iterable output.
           'gateway' means WSGI entry function ??
        """
        mrbs = self.server.max_request_body_size
        if self.chunked_read:
            self.rfile = chunkedrfile(self.conn.rfile, mrbs)
        else:
            cl = int(self.inheaders.get("content-length", 0))
            if mrbs and mrbs < cl:
                if not self.sent_headers:
                    self.simple_response("413 request entity too large",
                        "the entity sent with the request exceeds the maximum "
                        "allowed bytes.")
                return
            self.rfile = knownlengthrfile(self.conn.rfile, cl)
        
        # ==================================
        # see line 2061
        self.server.gateway(self).respond()
        
        if (self.ready and not self.sent_headers):
            self.sent_headers = true
            self.send_headers()
        if self.chunked_write:
            self.conn.wfile.sendall("0\r\n\r\n")
    
    def simple_response(self, status, msg=""):
        """write a simple response back to the client."""
        status = str(status)
        buf = [self.server.protocol + " " +
               status + crlf,
               "content-length: %s\r\n" % len(msg),
               "content-type: text/plain\r\n"]
        
        if status[:3] in ("413", "414"):
            # request entity too large / request-uri too long
            self.close_connection = true
            if self.response_protocol == 'http/1.1':
                # this will not be true for 414, since read_request_line
                # usually raises 414 before reading the whole line, and we
                # therefore cannot know the proper response_protocol.
                buf.append("connection: close\r\n")
            else:
                # http/1.0 had no 413/414 status nor connection header.
                # emit 400 instead and trust the message body is enough.
                status = "400 bad request"
        
        buf.append(crlf)
        if msg:
            if isinstance(msg, unicode):
                msg = msg.encode("iso-8859-1")
            buf.append(msg)
        
        try:
            self.conn.wfile.sendall("".join(buf))
        except socket.error, x:
            if x.args[0] not in socket_errors_to_ignore:
                raise
    
    def write(self, chunk):
        """write unbuffered data to the client."""
        if self.chunked_write and chunk:
            buf = [hex(len(chunk))[2:], crlf, chunk, crlf]
            self.conn.wfile.sendall("".join(buf))
        else:
            self.conn.wfile.sendall(chunk)
    
    def send_headers(self):
        """assert, process, and send the http response message-headers.
        
        you must set self.status, and self.outheaders before calling this.
        """
        hkeys = [key.lower() for key, value in self.outheaders]
        status = int(self.status[:3])
        
        if status == 413:
            # request entity too large. close conn to avoid garbage.
            self.close_connection = true
        elif "content-length" not in hkeys:
            # "all 1xx (informational), 204 (no content),
            # and 304 (not modified) responses must not
            # include a message-body." so no point chunking.
            if status < 200 or status in (204, 205, 304):
                pass
            else:
                if (self.response_protocol == 'http/1.1'
                    and self.method != 'head'):
                    # use the chunked transfer-coding
                    self.chunked_write = true
                    self.outheaders.append(("transfer-encoding", "chunked"))
                else:
                    # closing the conn is the only way to determine len.
                    self.close_connection = true
        
        if "connection" not in hkeys:
            if self.response_protocol == 'http/1.1':
                # both server and client are http/1.1 or better
                if self.close_connection:
                    self.outheaders.append(("connection", "close"))
            else:
                # server and/or client are http/1.0
                if not self.close_connection:
                    self.outheaders.append(("connection", "keep-alive"))
        
        if (not self.close_connection) and (not self.chunked_read):
            # read any remaining request body data on the socket.
            # "if an origin server receives a request that does not include an
            # expect request-header field with the "100-continue" expectation,
            # the request includes a request body, and the server responds
            # with a final status code before reading the entire request body
            # from the transport connection, then the server should not close
            # the transport connection until it has read the entire request,
            # or until the client closes the connection. otherwise, the client
            # might not reliably receive the response message. however, this
            # requirement is not be construed as preventing a server from
            # defending itself against denial-of-service attacks, or from
            # badly broken client implementations."
            remaining = getattr(self.rfile, 'remaining', 0)
            if remaining > 0:
                self.rfile.read(remaining)
        
        if "date" not in hkeys:
            self.outheaders.append(("date", rfc822.formatdate()))
        
        if "server" not in hkeys:
            self.outheaders.append(("server", self.server.server_name))
        
        buf = [self.server.protocol + " " + self.status + crlf]
        for k, v in self.outheaders:
            buf.append(k + ": " + v + crlf)
        buf.append(crlf)
        self.conn.wfile.sendall("".join(buf))
# ------------------------------------------------------------------------------------

class nosslerror(exception):
    """exception raised when a client speaks http to an https socket."""
    pass


class fatalsslalert(exception):
    """exception raised when the ssl implementation signals a fatal alert."""
    pass


# ------------------------------------------------------------------------------------
# read/write text from socket detail
class cp_fileobject(socket._fileobject):
    """faux file object attached to a socket object."""

    def __init__(self, *args, **kwargs):
        self.bytes_read = 0
        self.bytes_written = 0
        socket._fileobject.__init__(self, *args, **kwargs)
    
    def sendall(self, data):
        """sendall for non-blocking sockets."""
        while data:
            try:
                bytes_sent = self.send(data)
                data = data[bytes_sent:]
            except socket.error, e:
                if e.args[0] not in socket_errors_nonblocking:
                    raise

    def send(self, data):
        bytes_sent = self._sock.send(data)
        self.bytes_written += bytes_sent
        return bytes_sent

    def flush(self):
        if self._wbuf:
            buffer = "".join(self._wbuf)
            self._wbuf = []
            self.sendall(buffer)

    def recv(self, size):
        while true:
            try:
                data = self._sock.recv(size)
                self.bytes_read += len(data)
                return data
            except socket.error, e:
                if (e.args[0] not in socket_errors_nonblocking
                    and e.args[0] not in socket_error_eintr):
                    raise

    if not _fileobject_uses_str_type:
        def read(self, size=-1):
            # use max, disallow tiny reads in a loop as they are very inefficient.
            # we never leave read() with any leftover data from a new recv() call
            # in our internal buffer.
            rbufsize = max(self._rbufsize, self.default_bufsize)
            # our use of stringio rather than lists of string objects returned by
            # recv() minimizes memory usage and fragmentation that occurs when
            # rbufsize is large compared to the typical return value of recv().
            buf = self._rbuf
            buf.seek(0, 2)  # seek end
            if size < 0:
                # read until eof
                self._rbuf = stringio.stringio()  # reset _rbuf.  we consume it via buf.
                while true:
                    data = self.recv(rbufsize)
                    if not data:
                        break
                    buf.write(data)
                return buf.getvalue()
            else:
                # read until size bytes or eof seen, whichever comes first
                buf_len = buf.tell()
                if buf_len >= size:
                    # already have size bytes in our buffer?  extract and return.
                    buf.seek(0)
                    rv = buf.read(size)
                    self._rbuf = stringio.stringio()
                    self._rbuf.write(buf.read())
                    return rv

                self._rbuf = stringio.stringio()  # reset _rbuf.  we consume it via buf.
                while true:
                    left = size - buf_len
                    # recv() will malloc the amount of memory given as its
                    # parameter even though it often returns much less data
                    # than that.  the returned data string is short lived
                    # as we copy it into a stringio and free it.  this avoids
                    # fragmentation issues on many platforms.
                    data = self.recv(left)
                    if not data:
                        break
                    n = len(data)
                    if n == size and not buf_len:
                        # shortcut.  avoid buffer data copies when:
                        # - we have no data in our buffer.
                        # and
                        # - our call to recv returned exactly the
                        #   number of bytes we were asked to read.
                        return data
                    if n == left:
                        buf.write(data)
                        del data  # explicit free
                        break
                    assert n <= left, "recv(%d) returned %d bytes" % (left, n)
                    buf.write(data)
                    buf_len += n
                    del data  # explicit free
                    #assert buf_len == buf.tell()
                return buf.getvalue()

        def readline(self, size=-1):
            buf = self._rbuf
            buf.seek(0, 2)  # seek end
            if buf.tell() > 0:
                # check if we already have it in our buffer
                buf.seek(0)
                bline = buf.readline(size)
                if bline.endswith('\n') or len(bline) == size:
                    self._rbuf = stringio.stringio()
                    self._rbuf.write(buf.read())
                    return bline
                del bline
            if size < 0:
                # read until \n or eof, whichever comes first
                if self._rbufsize <= 1:
                    # speed up unbuffered case
                    buf.seek(0)
                    buffers = [buf.read()]
                    self._rbuf = stringio.stringio()  # reset _rbuf.  we consume it via buf.
                    data = none
                    recv = self.recv
                    while data != "\n":
                        data = recv(1)
                        if not data:
                            break
                        buffers.append(data)
                    return "".join(buffers)

                buf.seek(0, 2)  # seek end
                self._rbuf = stringio.stringio()  # reset _rbuf.  we consume it via buf.
                while true:
                    data = self.recv(self._rbufsize)
                    if not data:
                        break
                    nl = data.find('\n')
                    if nl >= 0:
                        nl += 1
                        buf.write(data[:nl])
                        self._rbuf.write(data[nl:])
                        del data
                        break
                    buf.write(data)
                return buf.getvalue()
            else:
                # read until size bytes or \n or eof seen, whichever comes first
                buf.seek(0, 2)  # seek end
                buf_len = buf.tell()
                if buf_len >= size:
                    buf.seek(0)
                    rv = buf.read(size)
                    self._rbuf = stringio.stringio()
                    self._rbuf.write(buf.read())
                    return rv
                self._rbuf = stringio.stringio()  # reset _rbuf.  we consume it via buf.
                while true:
                    data = self.recv(self._rbufsize)
                    if not data:
                        break
                    left = size - buf_len
                    # did we just receive a newline?
                    nl = data.find('\n', 0, left)
                    if nl >= 0:
                        nl += 1
                        # save the excess data to _rbuf
                        self._rbuf.write(data[nl:])
                        if buf_len:
                            buf.write(data[:nl])
                            break
                        else:
                            # shortcut.  avoid data copy through buf when returning
                            # a substring of our first recv().
                            return data[:nl]
                    n = len(data)
                    if n == size and not buf_len:
                        # shortcut.  avoid data copy through buf when
                        # returning exactly all of our first recv().
                        return data
                    if n >= left:
                        buf.write(data[:left])
                        self._rbuf.write(data[left:])
                        break
                    buf.write(data)
                    buf_len += n
                    #assert buf_len == buf.tell()
                return buf.getvalue()
    else:
        def read(self, size=-1):
            if size < 0:
                # read until eof
                buffers = [self._rbuf]
                self._rbuf = ""
                if self._rbufsize <= 1:
                    recv_size = self.default_bufsize
                else:
                    recv_size = self._rbufsize

                while true:
                    data = self.recv(recv_size)
                    if not data:
                        break
                    buffers.append(data)
                return "".join(buffers)
            else:
                # read until size bytes or eof seen, whichever comes first
                data = self._rbuf
                buf_len = len(data)
                if buf_len >= size:
                    self._rbuf = data[size:]
                    return data[:size]
                buffers = []
                if data:
                    buffers.append(data)
                self._rbuf = ""
                while true:
                    left = size - buf_len
                    recv_size = max(self._rbufsize, left)
                    data = self.recv(recv_size)
                    if not data:
                        break
                    buffers.append(data)
                    n = len(data)
                    if n >= left:
                        self._rbuf = data[left:]
                        buffers[-1] = data[:left]
                        break
                    buf_len += n
                return "".join(buffers)

        def readline(self, size=-1):
            data = self._rbuf
            if size < 0:
                # read until \n or eof, whichever comes first
                if self._rbufsize <= 1:
                    # speed up unbuffered case
                    assert data == ""
                    buffers = []
                    while data != "\n":
                        data = self.recv(1)
                        if not data:
                            break
                        buffers.append(data)
                    return "".join(buffers)
                nl = data.find('\n')
                if nl >= 0:
                    nl += 1
                    self._rbuf = data[nl:]
                    return data[:nl]
                buffers = []
                if data:
                    buffers.append(data)
                self._rbuf = ""
                while true:
                    data = self.recv(self._rbufsize)
                    if not data:
                        break
                    buffers.append(data)
                    nl = data.find('\n')
                    if nl >= 0:
                        nl += 1
                        self._rbuf = data[nl:]
                        buffers[-1] = data[:nl]
                        break
                return "".join(buffers)
            else:
                # read until size bytes or \n or eof seen, whichever comes first
                nl = data.find('\n', 0, size)
                if nl >= 0:
                    nl += 1
                    self._rbuf = data[nl:]
                    return data[:nl]
                buf_len = len(data)
                if buf_len >= size:
                    self._rbuf = data[size:]
                    return data[:size]
                buffers = []
                if data:
                    buffers.append(data)
                self._rbuf = ""
                while true:
                    data = self.recv(self._rbufsize)
                    if not data:
                        break
                    buffers.append(data)
                    left = size - buf_len
                    nl = data.find('\n', 0, left)
                    if nl >= 0:
                        nl += 1
                        self._rbuf = data[nl:]
                        buffers[-1] = data[:nl]
                        break
                    n = len(data)
                    if n >= left:
                        self._rbuf = data[left:]
                        buffers[-1] = data[:left]
                        break
                    buf_len += n
                return "".join(buffers)

class httpconnection(object):
    """an http connection (active socket).
    
    server: the server object which received this connection.
    socket: the raw socket object (usually tcp) for this connection.
    makefile: a fileobject class for reading from the socket.
    """
    remote_addr = none
    remote_port = none
    ssl_env = none
    rbufsize = default_buffer_size
    wbufsize = default_buffer_size
    requesthandlerclass = httprequest
    
    def __init__(self, server, sock, makefile=cp_fileobject):
        self.server = server
        self.socket = sock
        self.rfile = makefile(sock, "rb", self.rbufsize)
        self.wfile = makefile(sock, "wb", self.wbufsize)
        self.requests_seen = 0
    
    def communicate(self):
        """read each request and respond appropriately."""
        request_seen = false
        try:
            while true:
                # (re)set req to none so that if something goes wrong in
                # the requesthandlerclass constructor, the error doesn't
                # get written to the previous request.
                req = none
                req = self.requesthandlerclass(self.server, self)
                
                # this order of operations should guarantee correct pipelining.
                req.parse_request()
                if self.server.stats['enabled']:
                    self.requests_seen += 1
                if not req.ready:
                    # something went wrong in the parsing (and the server has
                    # probably already made a simple_response). return and
                    # let the conn close.
                    return
                
                request_seen = true
                req.respond()
                if req.close_connection:
                    return
        except socket.error, e:
            errnum = e.args[0]
            # sadly ssl sockets return a different (longer) time out string
            if errnum == 'timed out' or errnum == 'the read operation timed out':
                # don't error if we're between requests; only error
                # if 1) no request has been started at all, or 2) we're
                # in the middle of a request.
                # see http://www.cherrypy.org/ticket/853
                if (not request_seen) or (req and req.started_request):
                    # don't bother writing the 408 if the response
                    # has already started being written.
                    if req and not req.sent_headers:
                        try:
                            req.simple_response("408 request timeout")
                        except fatalsslalert:
                            # close the connection.
                            return
            elif errnum not in socket_errors_to_ignore:
                if req and not req.sent_headers:
                    try:
                        req.simple_response("500 internal server error",
                                            format_exc())
                    except fatalsslalert:
                        # close the connection.
                        return
            return
        except (keyboardinterrupt, systemexit):
            raise
        except fatalsslalert:
            # close the connection.
            return
        except nosslerror:
            if req and not req.sent_headers:
                # unwrap our wfile
                self.wfile = cp_fileobject(self.socket._sock, "wb", self.wbufsize)
                req.simple_response("400 bad request",
                    "the client sent a plain http request, but "
                    "this server only speaks https on this port.")
                self.linger = true
        except exception:
            if req and not req.sent_headers:
                try:
                    req.simple_response("500 internal server error", format_exc())
                except fatalsslalert:
                    # close the connection.
                    return
    
    linger = false
    
    def close(self):
        """close the socket underlying this connection."""
        self.rfile.close()
        
        if not self.linger:
            # python's socket module does not call close on the kernel socket
            # when you call socket.close(). we do so manually here because we
            # want this server to send a fin tcp segment immediately. note this
            # must be called *before* calling socket.close(), because the latter
            # drops its reference to the kernel socket.
            if hasattr(self.socket, '_sock'):
                self.socket._sock.close()
            self.socket.close()
        else:
            # on the other hand, sometimes we want to hang around for a bit
            # to make sure the client has a chance to read our entire
            # response. skipping the close() calls here delays the fin
            # packet until the socket object is garbage-collected later.
            # someday, perhaps, we'll do the full lingering_close that
            # apache does, but not today.
            pass
# ------------------------------------------------------------------------------------

_shutdownrequest = none

# ------------------------------------------------------------------------------------
# consumer thread
class workerthread(threading.thread):
    """thread which continuously polls a queue for connection objects.
    
    due to the timing issues of polling a queue, a workerthread does not
    check its own 'ready' flag after it has started. to stop the thread,
    it is necessary to stick a _shutdownrequest object onto the queue
    (one for each running workerthread).
    """
    
    conn = none
    """the current connection pulled off the queue, or none."""
    
    server = none
    """the http server which spawned this thread, and which owns the
    queue and is placing active connections into it."""
    
    ready = false
    """a simple flag for the calling server to know when this thread
    has begun polling the queue."""
    
    
    def __init__(self, server):
        self.ready = false
        self.server = server
        
        self.requests_seen = 0
        self.bytes_read = 0
        self.bytes_written = 0
        self.start_time = none
        self.work_time = 0
        self.stats = {
            'requests': lambda s: self.requests_seen + ((self.start_time is none) and 0 or self.conn.requests_seen),
            'bytes read': lambda s: self.bytes_read + ((self.start_time is none) and 0 or self.conn.rfile.bytes_read),
            'bytes written': lambda s: self.bytes_written + ((self.start_time is none) and 0 or self.conn.wfile.bytes_written),
            'work time': lambda s: self.work_time + ((self.start_time is none) and 0 or time.time() - self.start_time),
            'read throughput': lambda s: s['bytes read'](s) / (s['work time'](s) or 1e-6),
            'write throughput': lambda s: s['bytes written'](s) / (s['work time'](s) or 1e-6),
        }
        threading.thread.__init__(self)
    
    def run(self):
        self.server.stats['worker threads'][self.getname()] = self.stats
        try:
            self.ready = true
            while true:
                conn = self.server.requests.get()
                if conn is _shutdownrequest:
                    return
                
                self.conn = conn
                if self.server.stats['enabled']:
                    self.start_time = time.time()
                try:
                    conn.communicate()
                finally:
                    conn.close()
                    if self.server.stats['enabled']:
                        self.requests_seen += self.conn.requests_seen
                        self.bytes_read += self.conn.rfile.bytes_read
                        self.bytes_written += self.conn.wfile.bytes_written
                        self.work_time += time.time() - self.start_time
                        self.start_time = none
                    self.conn = none
        except (keyboardinterrupt, systemexit), exc:
            self.server.interrupt = exc


class threadpool(object):
    """a request queue for the cherrypywsgiserver which pools threads.
    
    threadpool objects must provide min, get(), put(obj), start()
    and stop(timeout) attributes.
    """
    
    def __init__(self, server, min=10, max=-1):
        self.server = server
        self.min = min
        self.max = max
        self._threads = []
        self._queue = queue.queue()
        self.get = self._queue.get
    
    def start(self):
        """start the pool of threads."""
        for i in range(self.min):
            self._threads.append(workerthread(self.server))
        for worker in self._threads:
            worker.setname("cp server " + worker.getname())
            worker.start()
        for worker in self._threads:
            while not worker.ready:
                time.sleep(.1)
    
    def _get_idle(self):
        """number of worker threads which are idle. read-only."""
        return len([t for t in self._threads if t.conn is none])
    idle = property(_get_idle, doc=_get_idle.__doc__)
    
    def put(self, obj):
        self._queue.put(obj)
        if obj is _shutdownrequest:
            return
    
    def grow(self, amount):
        """spawn new worker threads (not above self.max)."""
        for i in range(amount):
            if self.max > 0 and len(self._threads) >= self.max:
                break
            worker = workerthread(self.server)
            worker.setname("cp server " + worker.getname())
            self._threads.append(worker)
            worker.start()
    
    def shrink(self, amount):
        """kill off worker threads (not below self.min)."""
        # grow/shrink the pool if necessary.
        # remove any dead threads from our list
        for t in self._threads:
            if not t.isalive():
                self._threads.remove(t)
                amount -= 1
        
        if amount > 0:
            for i in range(min(amount, len(self._threads) - self.min)):
                # put a number of shutdown requests on the queue equal
                # to 'amount'. once each of those is processed by a worker,
                # that worker will terminate and be culled from our list
                # in self.put.
                self._queue.put(_shutdownrequest)
    
    def stop(self, timeout=5):
        # must shut down threads here so the code that calls
        # this method can know when all threads are stopped.
        for worker in self._threads:
            self._queue.put(_shutdownrequest)
        
        # don't join currentthread (when stop is called inside a request).
        current = threading.currentthread()
        if timeout and timeout >= 0:
            endtime = time.time() + timeout
        while self._threads:
            worker = self._threads.pop()
            if worker is not current and worker.isalive():
                try:
                    if timeout is none or timeout < 0:
                        worker.join()
                    else:
                        remaining_time = endtime - time.time()
                        if remaining_time > 0:
                            worker.join(remaining_time)
                        if worker.isalive():
                            # we exhausted the timeout.
                            # forcibly shut down the socket.
                            c = worker.conn
                            if c and not c.rfile.closed:
                                try:
                                    c.socket.shutdown(socket.shut_rd)
                                except typeerror:
                                    # pyopenssl sockets don't take an arg
                                    c.socket.shutdown()
                            worker.join()
                except (assertionerror,
                        # ignore repeated ctrl-c.
                        # see http://www.cherrypy.org/ticket/691.
                        keyboardinterrupt), exc1:
                    pass
    
    def _get_qsize(self):
        return self._queue.qsize()
    qsize = property(_get_qsize)


try:
    import fcntl
except importerror:
    try:
        from ctypes import windll, winerror
    except importerror:
        def prevent_socket_inheritance(sock):
            """dummy function, since neither fcntl nor ctypes are available."""
            pass
    else:
        def prevent_socket_inheritance(sock):
            """mark the given socket fd as non-inheritable (windows)."""
            if not windll.kernel32.sethandleinformation(sock.fileno(), 1, 0):
                raise winerror()
else:
    def prevent_socket_inheritance(sock):
        """mark the given socket fd as non-inheritable (posix)."""
        fd = sock.fileno()
        old_flags = fcntl.fcntl(fd, fcntl.f_getfd)
        fcntl.fcntl(fd, fcntl.f_setfd, old_flags | fcntl.fd_cloexec)


# ---------------------------------------------------------------------------------
# SSL = secure socket layer, SSL其实是5次握手,比普通socket多了加解密的过程
# SSL means add encryption/decryption into normal socket communication 
# SSL其实就是用加了加解密的secure socket代替普通的socket !
class ssladapter(object):
    """base class for ssl driver library adapters.
    
    required methods:
    
        * ``wrap(sock) -> (wrapped socket, ssl environ dict)``
        * ``makefile(sock, mode='r', bufsize=default_buffer_size) -> socket file object``
    """
    
    def __init__(self, certificate, private_key, certificate_chain=none):
        self.certificate = certificate
        self.private_key = private_key
        self.certificate_chain = certificate_chain
    
    def wrap(self, sock):
        raise notimplemented
    
    def makefile(self, sock, mode='r', bufsize=default_buffer_size):
        raise notimplemented
# --------------------------------------------------------------------------------

# --------------------------------------------------------------------------------
# 显然这是个逐层向上的抽象过程: 把每一底层的细节抽象出来一个class给上层直接调用
# 从建立socket通信读写数据的细节,到封装httprequest对象,到封装httpconnection对象,
# 再到封装httpserver对象,
# 写代码就是抽象的面向对象的思路: httpserver调httpconnection调httprequest调socket.
# 模块的最外层给用户直接用的就是httpserver对象而已,里面的实现细节不用管.
# this is OOP !! 先层层封装,然后自顶向下调用,最后暴露顶层给外面使用.
class httpserver(object):
    """an http server."""
    
    _bind_addr = "127.0.0.1"
    _interrupt = none
    
    gateway = none
    """a gateway instance."""
    
    minthreads = none
    """the minimum number of worker threads to create (default 10)."""
    
    maxthreads = none
    """the maximum number of worker threads to create (default -1 = no limit)."""
    
    server_name = none
    """the name of the server; defaults to socket.gethostname()."""
    
    protocol = "http/1.1"
    """the version string to write in the status-line of all http responses.
    
    for example, "http/1.1" is the default. this also limits the supported
    features used in the response."""
    
    request_queue_size = 5
    """the 'backlog' arg to socket.listen(); max queued connections (default 5)."""
    
    shutdown_timeout = 5
    """the total time, in seconds, to wait for worker threads to cleanly exit."""
    
    timeout = 10
    """the timeout in seconds for accepted connections (default 10)."""
    
    version = "cherrypy/3.2.0"
    """a version string for the httpserver."""
    
    software = none
    """the value to set for the server_software entry in the wsgi environ.
    
    if none, this defaults to ``'%s server' % self.version``."""
    
    ready = false
    """an internal flag which marks whether the socket is accepting connections."""
    
    max_request_header_size = 0
    """the maximum size, in bytes, for request headers, or 0 for no limit."""
    
    max_request_body_size = 0
    """the maximum size, in bytes, for request bodies, or 0 for no limit."""
    
    nodelay = true
    """if true (the default since 3.1), sets the tcp_nodelay socket option."""
    
    connectionclass = httpconnection
    """the class to use for handling http connections."""
    
    ssl_adapter = none
    """an instance of ssladapter (or a subclass).
    
    you must have the corresponding ssl driver library installed."""
    
    def __init__(self, bind_addr, gateway, minthreads=10, maxthreads=-1,
                 server_name=none):
        self.bind_addr = bind_addr
        self.gateway = gateway
        
        # threadpool
        self.requests = threadpool(self, min=minthreads or 1, max=maxthreads)
        
        if not server_name:
            server_name = socket.gethostname()
        self.server_name = server_name
        self.clear_stats()
    
    def clear_stats(self):
        self._start_time = none
        self._run_time = 0
        self.stats = {
            'enabled': false,
            'bind address': lambda s: repr(self.bind_addr),
            'run time': lambda s: (not s['enabled']) and 0 or self.runtime(),
            'accepts': 0,
            'accepts/sec': lambda s: s['accepts'] / self.runtime(),
            'queue': lambda s: getattr(self.requests, "qsize", none),
            'threads': lambda s: len(getattr(self.requests, "_threads", [])),
            'threads idle': lambda s: getattr(self.requests, "idle", none),
            'socket errors': 0,
            'requests': lambda s: (not s['enabled']) and 0 or sum([w['requests'](w) for w
                                       in s['worker threads'].values()], 0),
            'bytes read': lambda s: (not s['enabled']) and 0 or sum([w['bytes read'](w) for w
                                         in s['worker threads'].values()], 0),
            'bytes written': lambda s: (not s['enabled']) and 0 or sum([w['bytes written'](w) for w
                                            in s['worker threads'].values()], 0),
            'work time': lambda s: (not s['enabled']) and 0 or sum([w['work time'](w) for w
                                         in s['worker threads'].values()], 0),
            'read throughput': lambda s: (not s['enabled']) and 0 or sum(
                [w['bytes read'](w) / (w['work time'](w) or 1e-6)
                 for w in s['worker threads'].values()], 0),
            'write throughput': lambda s: (not s['enabled']) and 0 or sum(
                [w['bytes written'](w) / (w['work time'](w) or 1e-6)
                 for w in s['worker threads'].values()], 0),
            'worker threads': {},
            }
        logging.statistics["cherrypy httpserver %d" % id(self)] = self.stats
    
    def runtime(self):
        if self._start_time is none:
            return self._run_time
        else:
            return self._run_time + (time.time() - self._start_time)
    
    def __str__(self):
        return "%s.%s(%r)" % (self.__module__, self.__class__.__name__,
                              self.bind_addr)
    
    def _get_bind_addr(self):
        return self._bind_addr
    def _set_bind_addr(self, value):
        if isinstance(value, tuple) and value[0] in ('', none):
            # despite the socket module docs, using '' does not
            # allow ai_passive to work. passing none instead
            # returns '0.0.0.0' like we want. in other words:
            #     host    ai_passive     result
            #      ''         y         192.168.x.y
            #      ''         n         192.168.x.y
            #     none        y         0.0.0.0
            #     none        n         127.0.0.1
            # but since you can get the same effect with an explicit
            # '0.0.0.0', we deny both the empty string and none as values.
            raise valueerror("host values of '' or none are not allowed. "
                             "use '0.0.0.0' (ipv4) or '::' (ipv6) instead "
                             "to listen on all active interfaces.")
        self._bind_addr = value
    bind_addr = property(_get_bind_addr, _set_bind_addr,
        doc="""the interface on which to listen for connections.
        
        for tcp sockets, a (host, port) tuple. host values may be any ipv4
        or ipv6 address, or any valid hostname. the string 'localhost' is a
        synonym for '127.0.0.1' (or '::1', if your hosts file prefers ipv6).
        the string '0.0.0.0' is a special ipv4 entry meaning "any active
        interface" (inaddr_any), and '::' is the similar in6addr_any for
        ipv6. the empty string or none are not allowed.
        
        for unix sockets, supply the filename as a string.""")
    
    def start(self):
        """run the server forever."""
        # we don't have to trap keyboardinterrupt or systemexit here,
        # because cherrpy.server already does so, calling self.stop() for us.
        # if you're using this server with another framework, you should
        # trap those exceptions in whatever code block calls start().
        self._interrupt = none
        
        if self.software is none:
            self.software = "%s server" % self.version
        
        # ssl backward compatibility
        if (self.ssl_adapter is none and
            getattr(self, 'ssl_certificate', none) and
            getattr(self, 'ssl_private_key', none)):
            warnings.warn(
                    "ssl attributes are deprecated in cherrypy 3.2, and will "
                    "be removed in cherrypy 3.3. use an ssl_adapter attribute "
                    "instead.",
                    deprecationwarning
                )
            try:
                from cherrypy.wsgiserver.ssl_pyopenssl import pyopenssladapter
            except importerror:
                pass
            else:
                self.ssl_adapter = pyopenssladapter(
                    self.ssl_certificate, self.ssl_private_key,
                    getattr(self, 'ssl_certificate_chain', none))
        
        # select the appropriate socket
        if isinstance(self.bind_addr, basestring):
            # af_unix socket
            
            # so we can reuse the socket...
            try: os.unlink(self.bind_addr)
            except: pass
            
            # so everyone can access the socket...
            try: os.chmod(self.bind_addr, 0777)
            except: pass
            
            info = [(socket.af_unix, socket.sock_stream, 0, "", self.bind_addr)]
        else:
            # af_inet or af_inet6 socket
            # get the correct address family for our host (allows ipv6 addresses)
            host, port = self.bind_addr
            try:
                info = socket.getaddrinfo(host, port, socket.af_unspec,
                                          socket.sock_stream, 0, socket.ai_passive)
            except socket.gaierror:
                if ':' in self.bind_addr[0]:
                    info = [(socket.af_inet6, socket.sock_stream,
                             0, "", self.bind_addr + (0, 0))]
                else:
                    info = [(socket.af_inet, socket.sock_stream,
                             0, "", self.bind_addr)]
        
        self.socket = none
        msg = "no socket could be created"
        for res in info:
            af, socktype, proto, canonname, sa = res
            try:
                self.bind(af, socktype, proto)
            except socket.error:
                if self.socket:
                    self.socket.close()
                self.socket = none
                continue
            break
        if not self.socket:
            raise socket.error(msg)
        
        # timeout so keyboardinterrupt can be caught on win32
        self.socket.settimeout(1)
        self.socket.listen(self.request_queue_size)
        
        # ------------------------------------------------------
        # create worker threads
        # self.requests = threadpool, start workerpool here 
        self.requests.start()
        
        self.ready = true
        self._start_time = time.time()
        while self.ready:
            self.tick()
            if self.interrupt:
                while self.interrupt is true:
                    # wait for self.stop() to complete. see _set_interrupt.
                    time.sleep(0.1)
                if self.interrupt:
                    raise self.interrupt
    
    def bind(self, family, type, proto=0):
        """create (or recreate) the actual socket object."""
        self.socket = socket.socket(family, type, proto)
        prevent_socket_inheritance(self.socket)
        self.socket.setsockopt(socket.sol_socket, socket.so_reuseaddr, 1)
        if self.nodelay and not isinstance(self.bind_addr, str):
            self.socket.setsockopt(socket.ipproto_tcp, socket.tcp_nodelay, 1)
        
        if self.ssl_adapter is not none:
            self.socket = self.ssl_adapter.bind(self.socket)
        
        # if listening on the ipv6 any address ('::' = in6addr_any),
        # activate dual-stack. see http://www.cherrypy.org/ticket/871.
        if (hasattr(socket, 'af_inet6') and family == socket.af_inet6
            and self.bind_addr[0] in ('::', '::0', '::0.0.0.0')):
            try:
                self.socket.setsockopt(socket.ipproto_ipv6, socket.ipv6_v6only, 0)
            except (attributeerror, socket.error):
                # apparently, the socket option is not available in
                # this machine's tcp stack
                pass
        
        self.socket.bind(self.bind_addr)
    
    def tick(self):
        """accept a new connection and put it on the queue."""
        try:
            s, addr = self.socket.accept()
            if self.stats['enabled']:
                self.stats['accepts'] += 1
            if not self.ready:
                return
            
            prevent_socket_inheritance(s)
            if hasattr(s, 'settimeout'):
                s.settimeout(self.timeout)
            
            makefile = cp_fileobject
            ssl_env = {}
            # if ssl cert and key are set, we try to be a secure http server
            if self.ssl_adapter is not none:
                try:
                    s, ssl_env = self.ssl_adapter.wrap(s)
                except nosslerror:
                    msg = ("the client sent a plain http request, but "
                           "this server only speaks https on this port.")
                    buf = ["%s 400 bad request\r\n" % self.protocol,
                           "content-length: %s\r\n" % len(msg),
                           "content-type: text/plain\r\n\r\n",
                           msg]
                    
                    wfile = cp_fileobject(s, "wb", default_buffer_size)
                    try:
                        wfile.sendall("".join(buf))
                    except socket.error, x:
                        if x.args[0] not in socket_errors_to_ignore:
                            raise
                    return
                if not s:
                    return
                makefile = self.ssl_adapter.makefile
                # re-apply our timeout since we may have a new socket object
                if hasattr(s, 'settimeout'):
                    s.settimeout(self.timeout)
            
            conn = self.connectionclass(self, s, makefile)
            
            if not isinstance(self.bind_addr, basestring):
                # optional values
                # until we do dns lookups, omit remote_host
                if addr is none: # sometimes this can happen
                    # figure out if af_inet or af_inet6.
                    if len(s.getsockname()) == 2:
                        # af_inet
                        addr = ('0.0.0.0', 0)
                    else:
                        # af_inet6
                        addr = ('::', 0)
                conn.remote_addr = addr[0]
                conn.remote_port = addr[1]
            
            conn.ssl_env = ssl_env
            
            self.requests.put(conn)
        except socket.timeout:
            # the only reason for the timeout in start() is so we can
            # notice keyboard interrupts on win32, which don't interrupt
            # accept() by default
            return
        except socket.error, x:
            if self.stats['enabled']:
                self.stats['socket errors'] += 1
            if x.args[0] in socket_error_eintr:
                # i *think* this is right. eintr should occur when a signal
                # is received during the accept() call; all docs say retry
                # the call, and i *think* i'm reading it right that python
                # will then go ahead and poll for and handle the signal
                # elsewhere. see http://www.cherrypy.org/ticket/707.
                return
            if x.args[0] in socket_errors_nonblocking:
                # just try again. see http://www.cherrypy.org/ticket/479.
                return
            if x.args[0] in socket_errors_to_ignore:
                # our socket was closed.
                # see http://www.cherrypy.org/ticket/686.
                return
            raise
    
    def _get_interrupt(self):
        return self._interrupt
    def _set_interrupt(self, interrupt):
        self._interrupt = true
        self.stop()
        self._interrupt = interrupt
    interrupt = property(_get_interrupt, _set_interrupt,
                         doc="set this to an exception instance to "
                             "interrupt the server.")
    
    def stop(self):
        """gracefully shutdown a server that is serving forever."""
        self.ready = false
        if self._start_time is not none:
            self._run_time += (time.time() - self._start_time)
        self._start_time = none
        
        sock = getattr(self, "socket", none)
        if sock:
            if not isinstance(self.bind_addr, basestring):
                # touch our own socket to make accept() return immediately.
                try:
                    host, port = sock.getsockname()[:2]
                except socket.error, x:
                    if x.args[0] not in socket_errors_to_ignore:
                        # changed to use error code and not message
                        # see http://www.cherrypy.org/ticket/860.
                        raise
                else:
                    # note that we're explicitly not using ai_passive,
                    # here, because we want an actual ip to touch.
                    # localhost won't work if we've bound to a public ip,
                    # but it will if we bound to '0.0.0.0' (inaddr_any).
                    for res in socket.getaddrinfo(host, port, socket.af_unspec,
                                                  socket.sock_stream):
                        af, socktype, proto, canonname, sa = res
                        s = none
                        try:
                            s = socket.socket(af, socktype, proto)
                            # see http://groups.google.com/group/cherrypy-users/
                            #        browse_frm/thread/bbfe5eb39c904fe0
                            s.settimeout(1.0)
                            s.connect((host, port))
                            s.close()
                        except socket.error:
                            if s:
                                s.close()
            if hasattr(sock, "close"):
                sock.close()
            self.socket = none
        
        self.requests.stop(self.shutdown_timeout)

# -------------------------------------------------------------------------------
# gateway ?? 网关 ?? WSGI ??
class gateway(object):
    
    def __init__(self, req):
        self.req = req
    
    def respond(self):
        raise notimplemented


# these may either be wsgiserver.ssladapter subclasses or the string names
# of such classes (in which case they will be lazily loaded).
ssl_adapters = {
    'builtin': 'cherrypy.wsgiserver.ssl_builtin.builtinssladapter',
    'pyopenssl': 'cherrypy.wsgiserver.ssl_pyopenssl.pyopenssladapter',
    }

def get_ssl_adapter_class(name='pyopenssl'):
    adapter = ssl_adapters[name.lower()]
    if isinstance(adapter, basestring):
        last_dot = adapter.rfind(".")
        attr_name = adapter[last_dot + 1:]
        mod_path = adapter[:last_dot]
        
        try:
            mod = sys.modules[mod_path]
            if mod is none:
                raise keyerror()
        except keyerror:
            # the last [''] is important.
            mod = __import__(mod_path, globals(), locals(), [''])
        
        # let an attributeerror propagate outward.
        try:
            adapter = getattr(mod, attr_name)
        except attributeerror:
            raise attributeerror("'%s' object has no attribute '%s'"
                                 % (mod_path, attr_name))
    return adapter

# ----------------------------wsgiserver wsgi stuff -------------------------------- #
class cherrypywsgiserver(httpserver):
    wsgi_version = (1, 0)

    # wsgi_app means webpy application(an application has router/handler staff in it)
    # wsgiserver -> wsgi gateway -> app ??
    def __init__(self, bind_addr, wsgi_app, numthreads=10, server_name=none,
                 max=-1, request_queue_size=5, timeout=10, shutdown_timeout=5):
        self.requests = threadpool(self, min=numthreads or 1, max=max)
        # wsgi app ?
        self.wsgi_app = wsgi_app
        # wsgi_gateways = {(1, 0): wsgigateway_10, ('u', 0): wsgigateway_u0}
        # wsgi has versions ?
        self.gateway = wsgi_gateways[self.wsgi_version]
        
        self.bind_addr = bind_addr
        if not server_name:
            server_name = socket.gethostname()
        self.server_name = server_name
        self.request_queue_size = request_queue_size
        
        self.timeout = timeout
        self.shutdown_timeout = shutdown_timeout
        self.clear_stats()
    
    def _get_numthreads(self):
        return self.requests.min
    def _set_numthreads(self, value):
        self.requests.min = value
    numthreads = property(_get_numthreads, _set_numthreads)


class wsgigateway(gateway):

    def __init__(self, req):
        self.req = req
        self.started_response = false
        self.env = self.get_environ()
        self.remaining_bytes_out = none
    
    def get_environ(self):
        """return a new environ dict targeting the given wsgi.version"""
        raise notimplemented
    
    def respond(self):
        # ======================================================================
        # server.wsgi_app(env, start_response) is WSGI interface function ?
        # see application.py line 295 wsgi(env, start_resp) => server.wsgi_app
        response = self.req.server.wsgi_app(self.env, self.start_response)

        """usage: --------------------------------------------------------------
            # wsgi interface function:
            def my_crazy_app(environ, start_response):
                status = '200 ok'
                response_headers = [('content-type','text/plain')]
                start_response(status, response_headers)
                return ['hello world!']
            
            server = wsgiserver.cherrypywsgiserver(
                        ('0.0.0.0', 8070), my_crazy_app)
            server.start()
        --------------------------------------------------------------------"""
        # ======================================================================
        try:
            for chunk in response:
                # "the start_response callable must not actually transmit
                # the response headers. instead, it must store them for the
                # server or gateway to transmit only after the first
                # iteration of the application return value that yields
                # a non-empty string, or upon the application's first
                # invocation of the write() callable." (pep 333)
                if chunk:
                    if isinstance(chunk, unicode):
                        chunk = chunk.encode('iso-8859-1')
                    self.write(chunk)
        finally:
            if hasattr(response, "close"):
                response.close()
    
    def start_response(self, status, headers, exc_info = none):
        """wsgi callable to begin the http response."""
        # "the application may call start_response more than once,
        # if and only if the exc_info argument is provided."
        if self.started_response and not exc_info:
            raise assertionerror("wsgi start_response called a second "
                                 "time with no exc_info.")
        self.started_response = true
        
        # "if exc_info is provided, and the http headers have already been
        # sent, start_response must raise an error, and should raise the
        # exc_info tuple."
        if self.req.sent_headers:
            try:
                raise exc_info[0], exc_info[1], exc_info[2]
            finally:
                exc_info = none
        
        self.req.status = status
        for k, v in headers:
            if not isinstance(k, str):
                raise typeerror("wsgi response header key %r is not a byte string." % k)
            if not isinstance(v, str):
                raise typeerror("wsgi response header value %r is not a byte string." % v)
            if k.lower() == 'content-length':
                self.remaining_bytes_out = int(v)
        self.req.outheaders.extend(headers)
        
        return self.write
    
    def write(self, chunk):
        """wsgi callable to write unbuffered data to the client.
        
        this method is also used internally by start_response (to write
        data from the iterable returned by the wsgi application).
        """
        if not self.started_response:
            raise assertionerror("wsgi write called before start_response.")
        
        chunklen = len(chunk)
        rbo = self.remaining_bytes_out
        if rbo is not none and chunklen > rbo:
            if not self.req.sent_headers:
                # whew. we can send a 500 to the client.
                self.req.simple_response("500 internal server error",
                    "the requested resource returned more bytes than the "
                    "declared content-length.")
            else:
                # dang. we have probably already sent data. truncate the chunk
                # to fit (so the client doesn't hang) and raise an error later.
                chunk = chunk[:rbo]
        
        if not self.req.sent_headers:
            self.req.sent_headers = true
            self.req.send_headers()
        
        self.req.write(chunk)
        
        if rbo is not none:
            rbo -= chunklen
            if rbo < 0:
                raise valueerror(
                    "response body exceeds the declared content-length.")

class wsgigateway_10(wsgigateway):
    
    def get_environ(self):
        """return a new environ dict targeting the given wsgi.version"""
        req = self.req
        env = {
            # set a non-standard environ entry so the wsgi app can know what
            # the *real* server protocol is (and what features to support).
            # see http://www.faqs.org/rfcs/rfc2145.html.
            'actual_server_protocol': req.server.protocol,
            'path_info': req.path,
            'query_string': req.qs,
            'remote_addr': req.conn.remote_addr or '',
            'remote_port': str(req.conn.remote_port or ''),
            'request_method': req.method,
            'request_uri': req.uri,
            'script_name': '',
            'server_name': req.server.server_name,
            # bah. "server_protocol" is actually the request protocol.
            'server_protocol': req.request_protocol,
            'server_software': req.server.software,
            'wsgi.errors': sys.stderr,
            'wsgi.input': req.rfile,
            'wsgi.multiprocess': false,
            'wsgi.multithread': true,
            'wsgi.run_once': false,
            'wsgi.url_scheme': req.scheme,
            'wsgi.version': (1, 0),
            }
        
        if isinstance(req.server.bind_addr, basestring):
            # af_unix. this isn't really allowed by wsgi, which doesn't
            # address unix domain sockets. but it's better than nothing.
            env["server_port"] = ""
        else:
            env["server_port"] = str(req.server.bind_addr[1])
        
        # request headers
        for k, v in req.inheaders.iteritems():
            env["http_" + k.upper().replace("-", "_")] = v
        
        # content_type/content_length
        ct = env.pop("http_content_type", none)
        if ct is not none:
            env["content_type"] = ct
        cl = env.pop("http_content_length", none)
        if cl is not none:
            env["content_length"] = cl
        
        if req.conn.ssl_env:
            env.update(req.conn.ssl_env)
        
        return env

class wsgigateway_u0(wsgigateway_10):
    
    def get_environ(self):
        """return a new environ dict targeting the given wsgi.version"""
        req = self.req
        env_10 = wsgigateway_10.get_environ(self)
        env = dict([(k.decode('iso-8859-1'), v) for k, v in env_10.iteritems()])
        env[u'wsgi.version'] = ('u', 0)
        
        # request-uri
        env.setdefault(u'wsgi.url_encoding', u'utf-8')
        try:
            for key in [u"path_info", u"script_name", u"query_string"]:
                env[key] = env_10[str(key)].decode(env[u'wsgi.url_encoding'])
        except unicodedecodeerror:
            # fall back to latin 1 so apps can transcode if needed.
            env[u'wsgi.url_encoding'] = u'iso-8859-1'
            for key in [u"path_info", u"script_name", u"query_string"]:
                env[key] = env_10[str(key)].decode(env[u'wsgi.url_encoding'])
        
        for k, v in sorted(env.items()):
            if isinstance(v, str) and k not in ('request_uri', 'wsgi.input'):
                env[k] = v.decode('iso-8859-1')
        
        return env

wsgi_gateways = {
    (1, 0): wsgigateway_10,
    ('u', 0): wsgigateway_u0,
}
# ----------------------------------------------------------------------------------- #

class wsgipathinfodispatcher(object):
    """a wsgi dispatcher for dispatch based on the path_info.
    
    apps: a dict or list of (path_prefix, app) pairs.
    """
    
    def __init__(self, apps):
        try:
            apps = apps.items()
        except attributeerror:
            pass
        
        # sort the apps by len(path), descending
        apps.sort(cmp=lambda x,y: cmp(len(x[0]), len(y[0])))
        apps.reverse()
        
        # the path_prefix strings must start, but not end, with a slash.
        # use "" instead of "/".
        self.apps = [(p.rstrip("/"), a) for p, a in apps]
    
    def __call__(self, environ, start_response):
        path = environ["path_info"] or "/"
        for p, app in self.apps:
            # the apps list should be sorted by length, descending.
            if path.startswith(p + "/") or path == p:
                environ = environ.copy()
                environ["script_name"] = environ["script_name"] + p
                environ["path_info"] = path[len(p):]
                return app(environ, start_response)
        
        start_response('404 not found', [('content-type', 'text/plain'),
                                         ('content-length', '0')])
        return ['']


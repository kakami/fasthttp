// only used in client
package fasthttp

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"math"
	"sync/atomic"
	"time"
)

func readBodyCopy(r *bufio.Reader, contentLength int, w io.Writer) (int, error) {
	if contentLength == -1 {
		return copyBodyChunked(r, w)
	}
	if contentLength < 0 {
		contentLength = math.MaxInt64 / 2
	}
	return copyFixedSize(r, w, contentLength)
}

func copyFixedSize(r *bufio.Reader, w io.Writer, n int) (int, error) {
	b := make([]byte, 4096)
	var cnt, left, nn int
	var err error
	for {
		left = n - cnt
		if left <= 0 {
			break
		}
		if left > 4096 {
			left = 4096
		}
		nn, err = r.Read(b[:left])
		if nn <= 0 {
			if err != nil {
				if err == io.EOF {
					err = io.ErrUnexpectedEOF
				}
				return cnt, err
			}
		}
		wn, err := w.Write(b[:nn])
		if err != nil {
			return cnt, err
		}
		cnt += wn
	}
	return cnt, err
}

func copyBodyChunked(r *bufio.Reader, w io.Writer) (nn int, err error) {
	strCRLFlen := len(strCRLF)
	buf := make([]byte, strCRLFlen)
	var chunkSize, wn int
	for {
		chunkSize, err = parseChunkSize(r)
		if err != nil {
			return
		}
		wn, err = copyFixedSize(r, w, chunkSize)
		if err != nil {
			nn += wn
			return
		}
		nn += wn
		if _, err = r.Read(buf); err != nil {
			return
		}
		if !bytes.Equal(buf, strCRLF) {
			return nn, fmt.Errorf("cannot find crlf at the end of chunk")
		}
		if chunkSize == 0 {
			return
		}
	}
}

// HostClient
func (c *HostClient) DoCopy(req *Request, resp *Response, w io.Writer) error {
	var err error
	var retry bool
	maxAttempts := c.MaxIdemponentCallAttempts
	if maxAttempts <= 0 {
		maxAttempts = DefaultMaxIdemponentCallAttempts
	}
	isRequestRetryable := isIdempotent
	if c.RetryIf != nil {
		isRequestRetryable = c.RetryIf
	}
	attempts := 0
	hasBodyStream := req.IsBodyStream()

	atomic.AddInt32(&c.pendingRequests, 1)
	for {
		retry, err = c.doCopy(req, resp, w)
		if err == nil || !retry {
			break
		}

		if hasBodyStream {
			break
		}
		if !isRequestRetryable(req) {
			// Retry non-idempotent requests if the server closes
			// the connection before sending the response.
			//
			// This case is possible if the server closes the idle
			// keep-alive connection on timeout.
			//
			// Apache and nginx usually do this.
			if err != io.EOF {
				break
			}
		}
		attempts++
		if attempts >= maxAttempts {
			break
		}
	}
	atomic.AddInt32(&c.pendingRequests, -1)

	if err == io.EOF {
		err = ErrConnectionClosed
	}
	return err
}

func (c *HostClient) doCopy(req *Request, resp *Response, w io.Writer) (bool, error) {
	nilResp := false
	if resp == nil {
		nilResp = true
		resp = AcquireResponse()
	}

	ok, err := c.doNonNilReqRespCopy(req, resp, w)

	if nilResp {
		ReleaseResponse(resp)
	}

	return ok, err
}

func (c *HostClient) doNonNilReqRespCopy(req *Request, resp *Response, w io.Writer) (bool, error) {
	if req == nil {
		panic("BUG: req cannot be nil")
	}
	if resp == nil {
		panic("BUG: resp cannot be nil")
	}

	if c.IsTLS != bytes.Equal(req.uri.Scheme(), strHTTPS) {
		return false, ErrHostClientRedirectToDifferentScheme
	}

	atomic.StoreUint32(&c.lastUseTime, uint32(time.Now().Unix()-startTimeUnix))

	// Free up resources occupied by response before sending the request,
	// so the GC may reclaim these resources (e.g. response body).

	// backing up SkipBody in case it was set explicitly
	customSkipBody := resp.SkipBody
	resp.Reset()
	resp.SkipBody = customSkipBody

	if c.DisablePathNormalizing {
		req.URI().DisablePathNormalizing = true
	}

	cc, err := c.acquireConn(req.timeout)
	if err != nil {
		return false, err
	}
	conn := cc.c

	resp.parseNetConn(conn)

	if c.WriteTimeout > 0 {
		// Set Deadline every time, since golang has fixed the performance issue
		// See https://github.com/golang/go/issues/15133#issuecomment-271571395 for details
		currentTime := time.Now()
		if err = conn.SetWriteDeadline(currentTime.Add(c.WriteTimeout)); err != nil {
			c.closeConn(cc)
			return true, err
		}
	}

	resetConnection := false
	if c.MaxConnDuration > 0 && time.Since(cc.createdTime) > c.MaxConnDuration && !req.ConnectionClose() {
		req.SetConnectionClose()
		resetConnection = true
	}

	userAgentOld := req.Header.UserAgent()
	if len(userAgentOld) == 0 {
		req.Header.userAgent = append(req.Header.userAgent[:0], c.getClientName()...)
	}
	bw := c.acquireWriter(conn)
	err = req.Write(bw)

	if resetConnection {
		req.Header.ResetConnectionClose()
	}

	if err == nil {
		err = bw.Flush()
	}
	if err != nil {
		c.releaseWriter(bw)
		c.closeConn(cc)
		return true, err
	}
	c.releaseWriter(bw)

	if c.ReadTimeout > 0 {
		// Set Deadline every time, since golang has fixed the performance issue
		// See https://github.com/golang/go/issues/15133#issuecomment-271571395 for details
		currentTime := time.Now()
		if err = conn.SetReadDeadline(currentTime.Add(c.ReadTimeout)); err != nil {
			c.closeConn(cc)
			return true, err
		}
	}

	if customSkipBody || req.Header.IsHead() {
		resp.SkipBody = true
	}
	if c.DisableHeaderNamesNormalizing {
		resp.Header.DisableNormalizing()
	}

	br := c.acquireReader(conn)
	if err = resp.doBodyCopy(br, c.MaxResponseBodySize, w); err != nil {
		c.releaseReader(br)
		c.closeConn(cc)
		// Don't retry in case of ErrBodyTooLarge since we will just get the same again.
		retry := err != ErrBodyTooLarge
		return retry, err
	}
	c.releaseReader(br)

	if resetConnection || req.ConnectionClose() || resp.ConnectionClose() {
		c.closeConn(cc)
	} else {
		c.releaseConn(cc)
	}

	return false, err
}

func (resp *Response) doBodyCopy(r *bufio.Reader, maxBodySize int, w io.Writer) error {
	resp.resetSkipHeader()
	err := resp.Header.Read(r)
	if err != nil {
		return err
	}
	if resp.Header.StatusCode() == StatusContinue {
		// Read the next response according to http://www.w3.org/Protocols/rfc2616/rfc2616-sec8.html .
		if err = resp.Header.Read(r); err != nil {
			return err
		}
	}

	if !resp.mustSkipBody() {
		resp.bodyLength, err = readBodyCopy(r, resp.Header.ContentLength(), w)
		if err != nil {
			return err
		}
	}
	return nil
}

func (resp *Response) BodyLength() int {
	return resp.bodyLength
}

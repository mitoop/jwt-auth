<?php

namespace Tymon\JWTAuth\Http\Parser;

use Illuminate\Http\Request;
use Tymon\JWTAuth\Contracts\Http\Parser as ParserContract;

class TokenHeaders implements ParserContract
{
    /**
     * The header name.
     *
     * @var string
     */
    protected $header = 'X-Token';

    /**
     * Attempt to parse the token from some other possible headers.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return null|string
     */
    protected function fromAltHeaders(Request $request)
    {
        return $request->server->get('HTTP_X_TOKEN');
    }

    public function parse(Request $request)
    {
        return $request->headers->get($this->header) ?: $this->fromAltHeaders($request);
    }
}

<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth\Providers;

use Illuminate\Support\Arr;
use Tymon\JWTAuth\Http\Parser\AuthHeaders;
use Tymon\JWTAuth\Http\Parser\Cookies;
use Tymon\JWTAuth\Http\Parser\InputSource;
use Tymon\JWTAuth\Http\Parser\KeyTrait;
use Tymon\JWTAuth\Http\Parser\Parser;
use Tymon\JWTAuth\Http\Parser\QueryString;
use Tymon\JWTAuth\Http\Parser\RouteParams;
use Tymon\JWTAuth\Http\Parser\TokenHeaders;
use Tymon\JWTAuth\Token;

class LaravelServiceProvider extends AbstractServiceProvider
{
    /**
     * {@inheritdoc}
     */
    public function boot()
    {
        $path = realpath(__DIR__.'/../../config/config.php');

        $this->publishes([$path => config_path('jwt.php')], 'config');
        $this->mergeConfigFrom($path, 'jwt');

        $this->extendAuthGuard();
    }

    /**
     * {@inheritdoc}
     */
    protected function registerStorageProvider()
    {
        $this->app->singleton('tymon.jwt.provider.storage', function () {
            $instance = $this->getConfigInstance('providers.storage');

            if (method_exists($instance, 'setLaravelVersion')) {
                $instance->setLaravelVersion($this->app->version());
            }

            return $instance;
        });
    }

    /**
     * Register the bindings for the Token Parser.
     *
     * @return void
     */
    protected function registerTokenParser()
    {
        $this->app->singleton('tymon.jwt.parser', function ($app) {
            $parser = tap(new Parser($app['request']), function(Parser $parser){
                $options = $this->config('parsers');
                $chain = [];

                foreach ($options as $option){
                    if (str_contains(strtolower($option), 'cookie')) {
                        $option = new $option($this->config('decrypt_cookies'));
                    }else{
                        $option = new $option;
                    }

                    $chain[] = tap($option, function($option){
                        if (method_exists($option, 'setKey')) {
                            $option->setKey($this->config('parser_token_key', 'token'));
                        }
                    });
                }

                $parser->setChain($chain);
            });

            $app->refresh('request', $parser, 'setRequest');

            return $parser;
        });
    }

}

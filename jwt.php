<?php
/**
 * Class Jwt Jwt验证
 */

class Jwt
{
    // 头部
    private $header = array(
        'alg' => 'HS256', // 生成signature的算法
        'typ' => 'JWT'    // 类型
    );

    // 唯一令牌
    private $secret;

    // access_token 过期时间
    private $accessExp;

    // refresh_token 过期时间
    private $refreshExp;

    /**
     * 构造函数
     * @param string $secret 牌的secret值
     * @param float | int $accessExp access token 过期时间
     * @param float | int $refreshExp refresh token 过期时间
     */
    function __construct($secret, $accessExp = 60 * 60 * 2, $refreshExp = 60 * 60 * 24 * 30 * 3)
    {
        if (!$secret) {
            throw new Exception('secret can not be empty');
        }

        $this->secret = $secret;
        $this->accessExp = $accessExp;
        $this->refreshExp = $refreshExp;
    }

    /**
     * 生成access_token
     * @param int $identity 标识位
     * @return string
     */
    public function createAccessToken($identity)
    {
        return $this->sign(time() + $this->accessExp, $identity, 'jarl', 'access');
    }

    /**
     * 生成refresh_token
     * @param int $identity 标识位
     * @return string
     */
    public function createRefreshToken($identity)
    {
        return $this->sign(time() + $this->refreshExp, $identity, 'jarl', 'refresh');
    }

    /**
     * 验证token是否有效,默认验证exp,iat时间
     * @param string $token 需要验证的token
     * @param string $type 令牌的类型
     * @return bool|array
     */
    public function verifyToken($token, $type = 'access')
    {
        $tokens = explode('.', $token);
        if (count($tokens) != 3) {
            throw new Exception('验证失败');
        }

        list($base64header, $base64payload, $sign) = $tokens;

        //获取jwt算法
        $base64DecodeHeader = json_decode(self::base64UrlDecode($base64header), JSON_OBJECT_AS_ARRAY);
        if (empty($base64DecodeHeader['alg'])) {
            throw new Exception('Header验证失败');
        }

        //签名验证
        if (self::signature($base64header . '.' . $base64payload, $this->secret, $base64DecodeHeader['alg']) !== $sign) {
            throw new Exception('签名验证失败');
        }

        $payload = json_decode(self::base64UrlDecode($base64payload), JSON_OBJECT_AS_ARRAY);

        //签发时间大于当前服务器时间验证失败
        if (isset($payload['iat']) && $payload['iat'] > time()) {
            throw new Exception('验证失败');
        }

        //过期时间小宇当前服务器时间验证失败
        if (isset($payload['exp']) && $payload['exp'] < time()) {
            throw new Exception('已过期');
        }

        return $payload;
    }

    /**
     * 颁发令牌
     * @param int $identity 用户 id
     * @return array
     */
    public function getTokens($identity) {
        return array(
            'access_token' => $this->createAccessToken($identity),
            'refresh_token' => $this->createRefreshToken($identity)
        );
    }

    /**
     * 解析请求头
     * @param string $authorization Header authorization
     * @param string $type 令牌的类型
     * @return bool|array
     */
    public function parseHeader($authorization, $type = 'access') {
        $parts = explode(' ', $authorization);
        if (count($parts) === 2) {
            if ($parts[0] !== 'Bearer') {
                throw new Exception('解析失败');
            }
            return $this->verifyToken($parts[1], $type);
        } else {
            throw new Exception('解析失败');
        }
    }
    /**
     * 生成签名
     * @param string $exp 过期时间
     * @param int $identity 用户标识 唯一 id
     * @param string $scope 项目标识
     * @param string $type 类型 access 为 access_token refresh 为 refresh_token
     * @return string
     */
    private function sign($exp, $identity, $scope, $type)
    {
        $payload = array(
            //'iss'=>'jwt_admin',  //该JWT的签发者
            'iat' => time(), // 签发时间
            'exp'=>$exp,  //过期时间
            'identity' => $identity,
            'scope' => $scope,
            'type' => $type
            //'nbf'=>time()+60,  //该时间之前不接收处理该Token
            //'sub'=>'www.admin.com',  //面向的用户
            //'jti'=>md5(uniqid('JWT').time())  //该Token唯一标识
        );

        $base64header = self::base64UrlEncode(json_encode($this->header, JSON_UNESCAPED_UNICODE));
        $base64payload = self::base64UrlEncode(json_encode($payload, JSON_UNESCAPED_UNICODE));
        return $base64header.'.'.$base64payload.'.'.self::signature($base64header.'.'.$base64payload, $this->secret, $this->header['alg']);
    }

    /**
     * base64UrlEncode   https://jwt.io/  中base64UrlEncode编码实现
     * @param string $input 需要编码的字符串
     * @return string
     */
    private static function base64UrlEncode($input)
    {
        return str_replace('=', '', strtr(base64_encode($input), '+/', '-_'));
    }

    /**
     * base64UrlEncode  https://jwt.io/  中base64UrlEncode解码实现
     * @param string $input 需要解码的字符串
     * @return bool|string
     */
    private static function base64UrlDecode($input)
    {
        $remainder = strlen($input) % 4;
        if ($remainder) {
            $addlen = 4 - $remainder;
            $input .= str_repeat('=', $addlen);
        }
        return base64_decode(strtr($input, '-_', '+/'));
    }

    /**
     * HMACSHA256签名   https://jwt.io/  中HMACSHA256签名实现
     * @param string $input 为base64UrlEncode(header).".".base64UrlEncode(payload)
     * @param string $key
     * @param string $alg   算法方式
     * @return mixed
     */
    private static function signature($input, $key, $alg = 'HS256')
    {
        $alg_config=array(
            'HS256'=>'sha256'
        );
        return self::base64UrlEncode(hash_hmac($alg_config[$alg], $input, $key,true));
    }
}
<?php
/**
 * 使用DES对数据进行解密
 * @param string  $data   要加密的数据
 * @param string  $key    加密数据时候使用的密钥(64bit-->8byte密钥; 128bit-->16byte密钥; 256bit-->32byte密钥)
 * @param string  $iv     加密向量数据, 默认为: 0123456789123456
 * @return string   已解密的数据
 */
function des_encrypt($data, $key, $iv='0123456789123456', $padding="\0") {
    $blocksize = 16;
    $pad = $blocksize - (strlen($data) % $blocksize);       //计算填充长度
    $data = $data . str_repeat($padding, $pad);     //使用\0进行填充
    return bin2hex(mcrypt_encrypt(MCRYPT_DES, $key, $data, MCRYPT_MODE_ECB, $iv));
}

/**
 * 使用DES对数据进行解密
 * @param string  $data   要解密的数据
 * @param string  $key    加密数据时候使用的密钥(64bit-->8byte密钥; 128bit-->16byte密钥; 256bit-->32byte密钥)
 * @param string  $iv     加密向量数据, 默认为: 0123456789123456
 * @return string   已解密的数据
 */
function des_decrypt($data, $key, $iv='0123456789123456', $padding="\0") {
    //先进行解密, 最后对解密的数据进行填充去除
    return rtrim(mcrypt_decrypt(MCRYPT_DES, $key, hex2bin($data), MCRYPT_MODE_ECB, $iv), $padding);
}
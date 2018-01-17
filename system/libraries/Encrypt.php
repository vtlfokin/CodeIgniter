<?php  if ( ! defined('BASEPATH')) exit('No direct script access allowed');
/**
 * CodeIgniter
 *
 * An open source application development framework for PHP 5.1.6 or newer
 *
 * @package		CodeIgniter
 * @author		EllisLab Dev Team
 * @copyright		Copyright (c) 2008 - 2014, EllisLab, Inc.
 * @copyright		Copyright (c) 2014 - 2015, British Columbia Institute of Technology (http://bcit.ca/)
 * @license		http://codeigniter.com/user_guide/license.html
 * @link		http://codeigniter.com
 * @since		Version 1.0
 * @filesource
 */

// ------------------------------------------------------------------------

/**
 * CodeIgniter Encryption Class
 *
 * Provides two-way keyed encoding using openssl
 *
 * @package		CodeIgniter
 * @subpackage	Libraries
 * @category	Libraries
 * @author		EllisLab Dev Team
 * @link		http://codeigniter.com/user_guide/libraries/encryption.html
 */
class CI_Encrypt {

	/** @var CI_Controller */
	protected $CI;

	/**
	 * @var string
	 */
	protected $encryption_key = '';

	/**
	 * @var string
	 */
	protected $_hash_type = 'sha1';

	/**
	 * @var bool
	 */
	protected $_openssl_exists = FALSE;

	/**
	 * @var string
	 */
	protected $_openssl_cipher;

	/**
	 * @var int
	 */
	protected $encryptOptions = OPENSSL_ZERO_PADDING | OPENSSL_RAW_DATA;

	/**
	 * Constructor
	 *
	 * Simply determines whether the openssl library exists.
	 *
	 */
	public function __construct()
	{
		$this->CI =& get_instance();
		$this->_openssl_exists = (!function_exists('openssl_encrypt')) ? FALSE : TRUE;

		if ($this->_openssl_exists === FALSE) {
			show_error('The Encrypt library requires the Openssl.');
		}

		log_message('debug', "Encrypt Class Initialized");
	}

	// --------------------------------------------------------------------

	/**
	 * Fetch the encryption key
	 *
	 * Returns it as MD5 in order to have an exact-length 128 bit key.
	 * openssl is sensitive to keys that are not the correct length
	 *
	 * @access public
	 * @param string $key
	 * @return string
	 */
	public function get_key($key = '')
	{
		if ($key == '') {
			if ($this->encryption_key != '') {
				return $this->encryption_key;
			}

			$CI =& get_instance();
			$key = $CI->config->item('encryption_key');

			if ($key == FALSE) {
				show_error('In order to use the encryption class requires that you set an encryption key in your config file.');
			}
		}

		return md5($key);
	}

	// --------------------------------------------------------------------

	/**
	 * Set the encryption key
	 *
	 * @access public
	 * @param string $key
	 * @return void
	 */
	public function set_key($key = '')
	{
		$this->encryption_key = $key;
	}

	// --------------------------------------------------------------------

	/**
	 * Encode
	 *
	 * Encodes the message string using bitwise XOR encoding.
	 * The key is combined with a random hash, and then it
	 * too gets converted using XOR. The whole thing is then run
	 * through openssl using the randomized key. The end result
	 * is a double-encrypted message string that is randomized
	 * with each call to this function, even if the supplied
	 * message and key are the same.
	 *
	 * @access public
	 * @param string $string the string to encode
	 * @param string $key    the key
	 * @return string
	 */
	public function encode($string, $key = '')
	{
		$key = $this->get_key($key);
		$enc = $this->openssl_encode($string, $key);

		return base64_encode($enc);
	}

	// --------------------------------------------------------------------

	/**
	 * Decode
	 *
	 * Reverses the above process
	 *
	 * @access public
	 * @param string $string
	 * @param string $key
	 * @return string
	 */
	public function decode($string, $key = '')
	{
		$key = $this->get_key($key);

		if (preg_match('/[^a-zA-Z0-9\/\+=]/', $string)) {
			return FALSE;
		}

		$dec = base64_decode($string);

		if (($dec = $this->openssl_decode($dec, $key)) === FALSE) {
			return FALSE;
		}

		return $dec;
	}

	/**
	 * Encrypt using openssl
	 *
	 * @access protected
	 * @param string $data
	 * @param string $key
	 * @return string
	 */
	protected function openssl_encode($data, $key)
	{
		$init_size = \openssl_cipher_iv_length($this->_get_cipher());
		$init_vect = \openssl_random_pseudo_bytes($init_size);

		// Для совместимости с mcrypt
		$data_padded = $data;
		if (strlen($data_padded) % $init_size) {
			$padLength = strlen($data_padded) + $init_size - strlen($data_padded) % $init_size;
			$data_padded = str_pad($data_padded, $padLength, "\0");
		}

		$value = \openssl_encrypt(
			$data_padded,
			$this->_get_cipher(),
			$key,
			$this->encryptOptions,
			$init_vect
		);
		$value = $this->_add_cipher_noise($init_vect . $value, $key);

		return $value;
	}

	// --------------------------------------------------------------------

	/**
	 * Decrypt using Openssl
	 *
	 * @access protected
	 * @param string $data
	 * @param string $key
	 * @return string
	 */
	protected function openssl_decode($data, $key)
	{
		$data = $this->_remove_cipher_noise($data, $key);
		$init_size = openssl_cipher_iv_length($this->_get_cipher());

		if ($init_size > strlen($data)) {
			return null;
		}

		$init_vect = substr($data, 0, $init_size);
		$data = substr($data, $init_size);
		return rtrim(
			\openssl_decrypt(
				$data,
				$this->_get_cipher(),
				$key,
				$this->encryptOptions,
				$init_vect
			),
			"\0"
		);
	}

	// --------------------------------------------------------------------

	/**
	 * Adds permuted noise to the IV + encrypted data to protect
	 * against Man-in-the-middle attacks on CBC mode ciphers
	 * http://www.ciphersbyritter.com/GLOSSARY.HTM#IV
	 *
	 * Function description
	 *
	 * @access protected
	 * @param string $data
	 * @param string $key
	 * @return string
	 */
	protected function _add_cipher_noise($data, $key)
	{
		$keyhash = $this->hash($key);
		$keylen = strlen($keyhash);
		$str = '';

		for ($i = 0, $j = 0, $len = strlen($data); $i < $len; ++$i, ++$j) {
			if ($j >= $keylen) {
				$j = 0;
			}

			$str .= chr((ord($data[$i]) + ord($keyhash[$j])) % 256);
		}

		return $str;
	}

	// --------------------------------------------------------------------

	/**
	 * Removes permuted noise from the IV + encrypted data, reversing
	 * _add_cipher_noise()
	 *
	 * Function description
	 *
	 * @access protected
	 * @param string $data
	 * @param string $key
	 * @return string
	 */
	protected function _remove_cipher_noise($data, $key)
	{
		$keyhash = $this->hash($key);
		$keylen = strlen($keyhash);
		$str = '';

		for ($i = 0, $j = 0, $len = strlen($data); $i < $len; ++$i, ++$j) {
			if ($j >= $keylen) {
				$j = 0;
			}

			$temp = ord($data[$i]) - ord($keyhash[$j]);

			if ($temp < 0) {
				$temp = $temp + 256;
			}

			$str .= chr($temp);
		}

		return $str;
	}

	// --------------------------------------------------------------------

	/**
	 * Set the Openssl Cipher
	 *
	 * @access public
	 * @param string cipher
	 * @return void
	 */
	public function set_cipher($cipher)
	{
		$this->_openssl_cipher = $cipher;
	}

	// --------------------------------------------------------------------

	/**
	 * Get openssl cipher Value
	 *
	 * @access protected
	 * @return string
	 */
	protected function _get_cipher()
	{
		if (empty($this->_openssl_cipher)) {
			$this->_openssl_cipher = 'bf-cbc';
		}

		return $this->_openssl_cipher;
	}

	// --------------------------------------------------------------------

	// --------------------------------------------------------------------

	/**
	 * Set the Hash type
	 *
	 * @access public
	 * @param string $type
	 * @return string
	 */
	public function set_hash($type = 'sha1')
	{
		$this->_hash_type = ($type != 'sha1' AND $type != 'md5') ? 'sha1' : $type;
	}

	// --------------------------------------------------------------------

	/**
	 * Hash encode a string
	 *
	 * @access public
	 * @param string $str
	 * @return string
	 */
	public function hash($str)
	{
		return ($this->_hash_type == 'sha1') ? $this->sha1($str) : md5($str);
	}

	// --------------------------------------------------------------------

	/**
	 * Generate an SHA1 Hash
	 *
	 * @access public
	 * @param string $str
	 * @return string
	 */
	public function sha1($str)
	{
		if (!function_exists('sha1')) {
			if (!function_exists('mhash')) {
				require_once(BASEPATH . 'libraries/Sha1.php');
				$SH = new CI_SHA;

				return $SH->generate($str);
			} else {
				return bin2hex(mhash(MHASH_SHA1, $str));
			}
		} else {
			return sha1($str);
		}
	}

}

// END CI_Encrypt class

/* End of file Encrypt.php */
/* Location: ./system/libraries/Encrypt.php */

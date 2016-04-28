<?php

namespace Lychee\Modules;

final class Session {

	/**
	 * Reads and returns information about the Lychee installation.
	 * @return array Returns an array with the login status and configuration.
	 */
	public function init($public = true) {

		// Call plugins
		Plugins::get()->activate(__METHOD__, 0, func_get_args());

		// Return settings
		$return['config'] = Settings::get();

		// Path to Lychee for the server-import dialog
		$return['config']['location'] = LYCHEE;

		// Remove sensitive from response
		unset($return['config']['username']);
		unset($return['config']['password']);
		unset($return['config']['identifier']);

		// Check if login credentials exist and login if they don't
		if ($this->noLogin()===true) {
			$public = false;
			$return['config']['login'] = false;
		} else {
			$return['config']['login'] = true;
		}

		if ($public===false) {

			// Logged in
			$return['status'] = LYCHEE_STATUS_LOGGEDIN;

		} else {

			// Logged out
			$return['status'] = LYCHEE_STATUS_LOGGEDOUT;

			// Unset unused vars
			unset($return['config']['skipDuplicates']);
			unset($return['config']['sortingAlbums']);
			unset($return['config']['sortingPhotos']);
			unset($return['config']['dropboxKey']);
			unset($return['config']['login']);
			unset($return['config']['location']);
			unset($return['config']['imagick']);
			unset($return['config']['plugins']);

		}

		// Call plugins
		Plugins::get()->activate(__METHOD__, 1, func_get_args());

		return $return;

	}

	/**
	 * Sets the session values when username and password correct.
	 * @return boolean Returns true when login was successful.
	 */
	public function login($username, $password) {

		// Call plugins
		Plugins::get()->activate(__METHOD__, 0, func_get_args());

		if($this->radiusLogin($username, $password))
			return true;

		$username_crypt = crypt($username, Settings::get()['username']);
		$password_crypt = crypt($password, Settings::get()['password']);

		// Check login with crypted hash
		if (Settings::get()['username']===$username_crypt&&
			Settings::get()['password']===$password_crypt) {
				$_SESSION['login']      = true;
				$_SESSION['identifier'] = Settings::get()['identifier'];
				Log::notice(Database::get(), __METHOD__, __LINE__, 'User (' . $username . ') has logged in from ' . $_SERVER['REMOTE_ADDR']);
				return true;
		}

		// No login
		if ($this->noLogin()===true) return true;

		// Call plugins
		Plugins::get()->activate(__METHOD__, 1, func_get_args());

		// Log failed log in
		Log::error(Database::get(), __METHOD__, __LINE__, 'User (' . $username . ') has tried to log in from ' . $_SERVER['REMOTE_ADDR']);

		return false;

	}

	/**
	 * Attempts a login via radius
	 * @ return boolean Returns true when radius login was successfull.
	 */
	private function radiusLogin($username, $password) {

		$credentials = Config::get();

		if(!$this->is_arago($username))
			return false;

		if(empty($credentials['radius']['server']) || !preg_match("#^(s|m)[0-9]{0,7}#", $username))
			return false;

		$radius = radius_auth_open();
		$result = $radius !== false && radius_add_server($radius, $credentials['radius']['server'], 0, $credentials['radius']['token'], 2, 3);
		$result = $result !== false && radius_create_request($radius, RADIUS_ACCESS_REQUEST);

		if(!$result) {
			Log::error(Database::get(), __METHOD__, __LINE__, 'Radius connection has failed.');
			return false;
		}

		$radius_username = $username . $credentials['radius']['realm'];
		radius_put_attr($radius, RADIUS_USER_NAME, $radius_username);
		radius_put_attr($radius, RADIUS_USER_PASSWORD, $password);
		$result = radius_send_request($radius);

		if($result === RADIUS_ACCESS_ACCEPT) {
			$_SESSION['login']		= true;
			$_SESSION['identifier']	= Settings::get()['identifier'];
			$_SESSION['username']	= $username;
			return true;
		} else {
			Log::error(Database::get(), __METHOD__, __LINE__, 'User (' . $radius_username . ') has tried to log in from ' . $_SERVER['REMOTE_ADDR']. ' via Radius');
		}

		return false;
	}
	/**
	 * Check if the user is member of the student association
	 * @return boolean Returns true when the user is member of the student association S.V. Arago.
	 */
	private function is_arago($username) {
		$studentnr = substr($username, 1);
		$sql = "SELECT Studentnr FROM Ledendatabase.Naam WHERE Studentnr='$studentnr'";
		return Database::get()->query($sql)->num_rows > 0;
	}

	/**
	 * Sets the session values when no there is no username and password in the database.
	 * @return boolean Returns true when no login was found.
	 */
	private function noLogin() {

		// Check if login credentials exist and login if they don't
		if (Settings::get()['username']===''&&
			Settings::get()['password']==='') {
				$_SESSION['login']      = true;
				$_SESSION['identifier'] = Settings::get()['identifier'];
				return true;
		}

		return false;

	}

	/**
	 * Unsets the session values.
	 * @return boolean Returns true when logout was successful.
	 */
	public function logout() {

		// Call plugins
		Plugins::get()->activate(__METHOD__, 0, func_get_args());

		session_unset();
		session_destroy();

		// Call plugins
		Plugins::get()->activate(__METHOD__, 1, func_get_args());

		return true;

	}

}

?>
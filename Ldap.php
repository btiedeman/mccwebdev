<?php

/**
 * @package mccwebdev
 * @subpackage mccwebdev-yii2-ldap
 * @version 1.0.0
 */

namespace mccwebdev\ldap;

use yii\base\InvalidConfigException;

/**
 * This is just an example.
 */
class Ldap extends \yii\base\Component {
	
	const ERROR_LDAP_NONE = 0;
	const ERROR_LDAP_MULTIPLE_USERS_FOUND = 1; // search not specific enough
	const ERROR_LDAP_USERNAME_INVALID = 2;
	const ERROR_LDAP_PASSWORD_INVALID = 3;
	const ERROR_LDAP_UNAVAILABLE = 4;
	const ERROR_UNKNOWN_IDENTITY = 100;
	
	protected $connectionHostname;
	protected function getConnectionHostname( ) {
		return $this->connectionHostname;
	}
	protected function setConnectionHostname( $connectionHostname ) {
		$this->connectionHostname = $connectionHostname;
	}
	
	protected $connectionPort;
	protected function getConnectionPort( ) {
		return $this->connectionPort;
	}
	protected function setConnectionPort( $connectionPort ) {
		$this->connectionPort = $connectionPort;
	}
	
	protected $serviceDistinguishedName;
	protected function getServiceDistinguishedName( ) {
		return $this->serviceDistinguishedName;
	}
	protected function setServiceDistinguishedName( $serviceDistinguishedName ) {
		$this->serviceDistinguishedName = $serviceDistinguishedName;
	}
	
	protected $servicePassword;
	protected function getServicePassword( ) {
		return $this->servicePassword;
	}
	protected function setServicePassword( $servicePassword ) {
		$this->servicePassword = $servicePassword;
	}
	
	protected $searchBaseDistinguishedName;
	protected function getSearchBaseDistinguishedName( ) {
		return $this->searchBaseDistinguishedName;
	}
	protected function setSearchBaseDistinguishedName( $searchBaseDistinguishedName ) {
		$this->searchBaseDistinguishedName = $searchBaseDistinguishedName;
	}
	
	protected $searchParameters = [ ];
	protected function getSearchParameters( ) {
		return $this->searchParameters;
	}
	protected function setSearchParameters( $searchParameters ) {
		$this->searchParameters = $searchParameters;
	}
	
	protected $requestedAttributes = [ ];
	protected function getRequestedAttributes( ) {
		return $this->requestedAttributes;
	}
	protected function setRequestedAttributes( $requestedAttributes ) {
		$this->requestedAttributes = $requestedAttributes;
	}
	
	protected $userAttributes = [ ];
	
	protected $errorCode = self::ERROR_LDAP_NONE;
	
	private function getLdapConnection( ) {
		
		if( empty( $this->connectionHostname ) )
			throw new InvalidConfigException( "'connectionHostname' configuration cannot be empty." );
		if( empty( $this->connectionPort ) )
			throw new InvalidConfigException( "'connectionPort' configuration cannot be empty." );
		
		// try to connect to LDAP server
		$ldapConnection = ldap_connect( $this->connectionHostname, $this->connectionPort );
		if( ! $ldapConnection ):
			$this->errorCode = self::ERROR_LDAP_UNAVAILABLE;
			return NULL;
		endif;
		
		return $ldapConnection;
		
	}
	
	private function getLdapBinding( &$ldapConnection ) {
		
		if( empty( $this->serviceDistinguishedName ) )
			throw new InvalidConfigException( "'serviceDistinguishedName' configuration cannot be empty." );
		if( empty( $this->servicePassword ) )
			throw new InvalidConfigException( "'servicePassword' configuration cannot be empty." );
		
		// try to bind to LDAP server with authorized service account
		$ldapBind = ldap_bind( $ldapConnection, $this->serviceDistinguishedName, $this->servicePassword );
		if( ! $ldapBind ):
			ldap_unbind( $ldapConnection );
			$this->errorCode = self::ERROR_LDAP_UNAVAILABLE;
			return false;
		endif;
		
		return $ldapBind;
		
	}
	
	private function getLdapSearchResults( &$ldapConnection, $parameters ) {
		
		if( empty( $this->searchBaseDistinguishedName ) )
			throw new InvalidConfigException( "'searchBaseDistinguishedName' configuration cannot be empty." );
		
		// try to find the requested user and any requested attributes
		$ldapSearch = ldap_search( $ldapConnection, $this->searchBaseDistinguishedName, $this->buildLdapFilter( $parameters ) );
		$ldapSearchResults = ldap_get_entries( $ldapConnection, $ldapSearch );
		
		if( $ldapSearchResults[ 'count' ] > 1 ):
			ldap_unbind( $ldapConnection );
			$this->errorCode = self::ERROR_LDAP_MULTIPLE_USERS_FOUND;
			return false;
		endif;
		
		if( $ldapSearchResults[ 'count'] < 1 ):
			ldap_unbind( $ldapConnection );
			$this->errorCode = self::ERROR_LDAP_USERNAME_INVALID;
			return false;
		endif;
		
		$user = $ldapSearchResults[ 0 ];
		
		$this->userAttributes = [ ];
		if( ! empty( $this->requestedAttributes ) ):
			foreach( $this->requestedAttributes as $attributeName => $attribute ):
				$value = '';
				if( ! empty( $user[ $attribute[ 'id' ] ] ) ):
					$value = $user[ $attribute[ 'id' ] ];
					if( ( $value[ 'type' ] === 'single' ) && ( count( $value ) > 0 ) ):
						$value = $value[ 0 ];
					endif;
				endif;
				$this->userAttributes[ $attributeName ] = $value;
			endforeach;
		endif;
		
		return $user;
		
	}
	
	private function buildLdapFilter( $parameters ) {
		
		if( empty( $this->searchParameters ) )
			throw new InvalidConfigException( "'searchParameters' configuration cannot be empty." );
		
		$filters = [ ];
		foreach( $this->searchParameters as $searchParameter => $searchValue ):
			$filters[ ] = $searchParameter . '=' . $parameters[ $searchValue ];
		endforeach;
		return implode( ',', $filters );
		
	}
	
	private function checkPassword( &$ldapConnection, $userDistinguishedName, $password ) {
		
		// check if password is valid
		$ldapBind = @ldap_bind( $ldapConnection, $userDistinguishedName, $password );
		if( ! $ldapBind ):
			ldap_unbind( $ldapConnection );
			$this->errorCode = self::ERROR_LDAP_PASSWORD_INVALID;
			return false;
		endif;
		
		return true;
		
	}
	
	public function findUser( $username ) {
		
		$ldapConnection = NULL;
		$ldapBind = NULL;
		$user = NULL;
		
		// try to connect to LDAP server
		if( ! ( $ldapConnection = $this->getLdapConnection( ) ) ) return false;
		
		// set LDAP options
		// TODO: convert to Yii configuration
		ldap_set_option( $ldapConnection, LDAP_OPT_PROTOCOL_VERSION, 3 );
		ldap_set_option( $ldapConnection, LDAP_OPT_REFERRALS, 0 );
		
		// try to bind to LDAP server with authorized service account
		if( ! ( $ldapBind = $this->getLdapBinding( $ldapConnection ) ) ) return false;
		
		// try to find the requested user and any requested attributes
		if( ! ( $user = $this->getLdapSearchResults( $ldapConnection, [ 'username' => $username ] ) ) ) return false;
		
		// return success
		ldap_unbind( $ldapConnection );
		$this->errorCode = self::ERROR_LDAP_NONE;
		return true;
		
	}
	
	public function authenticateUser( $username, $password ) {
		
		$ldapConnection = NULL;
		$ldapBind = NULL;
		$user = NULL;
		
		// try to connect to LDAP server
		if( ! ( $ldapConnection = $this->getLdapConnection( ) ) ) return false;
		
		// set LDAP options
		// TODO: convert to Yii configuration
		ldap_set_option( $ldapConnection, LDAP_OPT_PROTOCOL_VERSION, 3 );
		ldap_set_option( $ldapConnection, LDAP_OPT_REFERRALS, 0 );
		
		// try to bind to LDAP server with authorized service account
		if( ! ( $ldapBind = $this->getLdapBinding( $ldapConnection ) ) ) return false;
		
		// try to find the requested user and any requested attributes
		if( ! ( $user = $this->getLdapSearchResults( $ldapConnection, [ 'username' => $username ] ) ) ) return false;
		
		// retrieve distinguished name
		$userDistinguishedName = ( empty( $user[ 'dn' ] ) ? '' : $user[ 'dn' ] );
		
		// check if password is valid
		if( ! ( $this->checkPassword( $ldapConnection, $userDistinguishedName, $password ) ) ) return false;
		
		// return success
		ldap_unbind( $ldapConnection );
		$this->errorCode = self::ERROR_LDAP_NONE;
		return true;
		
	}
	
	public function getUserAttributes( ) {
		return $this->userAttributes;
	}
	
	public function getErrorMessage( ) {
		
		switch( $this->errorCode ):
			
			case ERROR_LDAP_NONE:
				return 'No error.';
				break;
			case ERROR_LDAP_MULTIPLE_USERS_FOUND:
				return 'Could not distinguish user.';
				break;
			case ERROR_LDAP_USERNAME_INVALID:
				return 'Invalid username.';
				break;
			case ERROR_LDAP_PASSWORD_INVALID:
				return 'Invalid password.';
				break;
			case ERROR_LDAP_UNAVAILABLE:
				return 'Authentication service currently unavailable.';
				break;
			case ERROR_UNKNOWN_IDENTITY:
			default:
				return 'Unknown error. Please contact an administrator.';
				break;
			
		endswitch;
		
	}
	
}


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
	protected $connectionPort;
	protected $serviceDistinguishedName;
	protected $servicePassword;
	
	protected $searchBaseDistinguishedName;
	protected $searchParameters = [ ];
	
	protected $username;
	protected $password;
	
	protected $requestedAttributes = [ ];
	protected $userAttributes = [ ];
	
	protected $errorCode = self::ERROR_LDAP_NONE;
	
	public function setCredentials( $username, $password ) {
		$this->username = $username;
		$this->password = $password;
	}
	
	public function authenticateUser( ) {
		
		if( empty( $this->connectionHostname ) )
			throw new InvalidConfigException( "'connectionHostname' configuration cannot be empty." );
		if( empty( $this->connectionPort ) )
			throw new InvalidConfigException( "'connectionPort' configuration cannot be empty." );
		if( empty( $this->serviceDistinguishedName ) )
			throw new InvalidConfigException( "'serviceDistinguishedName' configuration cannot be empty." );
		if( empty( $this->servicePassword ) )
			throw new InvalidConfigException( "'servicePassword' configuration cannot be empty." );
		if( empty( $this->searchBaseDistinguishedName ) )
			throw new InvalidConfigException( "'searchBaseDistinguishedName' configuration cannot be empty." );
		if( empty( $this->searchParameters ) )
			throw new InvalidConfigException( "'searchParameters' configuration cannot be empty." );
		
		$ldapConnection = NULL;
		$ldapBind = NULL;
		
		// try to connect to LDAP server
		$ldapConnection = ldap_connect( $this->connectionHostname, $this->connectionPort );
		if( ! $ldapConnection ):
			$this->errorCode = self::ERROR_LDAP_UNAVAILABLE;
			return false;
		endif;
		
		// set LDAP options
		// TODO: convert to Yii configuration
		ldap_set_option( $ldapConnection, LDAP_OPT_PROTOCOL_VERSION, 3 );
		ldap_set_option( $ldapConnection, LDAP_OPT_REFERRALS, 0 );
		
		// try to bind to LDAP server with authorized service account
		$ldapBind = ldap_bind( $ldapConnection, $this->serviceDistinguishedName, $this->servicePassword );
		if( ! $ldapBind ):
			ldap_unbind( $ldapConnection );
			$this->errorCode = self::ERROR_LDAP_UNAVAILABLE;
			return false;
		endif;
		
		// try to find the requested user
		$ldapSearch = ldap_search( $ldapConnection, $this->searchBaseDistinguishedName, $this->buildLdapFilter( ) );
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
		
		// retrieve distinguished name and any requested attributes
		$user = $ldapSearchResults[ 0 ];
		
		$userDN = ( empty( $requestedUser[ 'dn' ] ) ? '' : $requestedUser[ 'dn' ] );
		
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
		
		// check if password is valid
		$ldapBind = @ldap_bind( $ldapConnection, $userDN, $this->password );
		if( ! $ldapBind ):
			ldap_unbind( $ldapConnection );
			$this->errorCode = self::ERROR_LDAP_PASSWORD_INVALID;
			return false;
		endif;
		
		// return success
		ldap_unbind( $ldapConnection );
		$this->errorCode = self::ERROR_LDAP_NONE;
		return true;
		
	}
	
	private function buildLdapFilter( ) {
		
		$filters = [ ];
		foreach( $this->searchParameters as $searchParameter => $searchValue ):
			$filters[ ] = $searchParameter . '=' . $this->$searchValue;
		endforeach;
		return implode( ',', $filters );
		
	}
	
	public function getUserAttributes( ) {
		return $this->userAttributes;
	}
	
}


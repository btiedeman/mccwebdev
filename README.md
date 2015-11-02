Yii 2 Ldap Extension for Northwestern University
================================================
Yii 2 Ldap Extension for Northwestern University

Installation
------------

The preferred way to install this extension is through [composer](http://getcomposer.org/download/).

Either run

```
php composer.phar require --prefer-dist mccwebdev/bat008.yii2-ldap-nwu "*"
```

or add

```
"mccwebdev/bat008.yii2-ldap-nwu": "*"
```

to the require section of your `composer.json` file.


Usage
-----

Once the extension is installed, configure the component:

```
'ldap' => [
	'class' => '\mccwebdev\ldap\Ldap',
	'connectionHostname' => '========',
	'connectionPort' => '========',
	'serviceDistinguishedName' => '========',
	'servicePassword' => '========',
	'searchBaseDistinguishedName' => '========',
	'searchParameters' => [
		'uid' => 'username',
	],
	'requestedAttributes' => [
		'name' => [
			'id' => 'displayname',
			'type' => 'single',
		],
		'emailAddress' => [
			'id' => 'mail',
			'type' => 'single',
		],
		'schoolAffiliations' => [
			'id' => 'nuschoolaffiliations',
			'type' => 'multiple',
		],
	],
],
```

Finally, use the component wherever you need to find or authenticate an account.

```
$isUser = Yii::$app->ldap->findUser( );
$isAuthenticated = Yii::$app->ldap->authenticateUser( );
```

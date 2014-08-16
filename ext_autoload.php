<?php
// DO NOT CHANGE THIS FILE! It is automatically generated by extdeveval::buildAutoloadRegistry.
// This file was generated on 2010-07-06 16:13

$extensionPath = t3lib_extMgm::extPath('ig_ldap_sso_auth');
$autoload = array(
	'tx_igldapssoauth_scheduler_synchroniseusers' => $extensionPath . 'Classes/Library/SchedulerSynchroniseusers.php',
	'tx_igldapssoauth_auth'				=>	$extensionPath . 'Classes/Library/Auth.php',
	'tx_igldapssoauth_config'			=>	$extensionPath . 'Classes/Library/Config.php',
	'tx_igldapssoauth_ldap_group'		=>	$extensionPath . 'Classes/Library/LdapGroup.php',
	'tx_igldapssoauth_ldap_user'		=>	$extensionPath . 'Classes/Library/LdapUser.php',
	'tx_igldapssoauth_ldap'				=>	$extensionPath . 'Classes/Library/Ldap.php',
	'tx_igldapssoauth_tca_form_suggest'	=>	$extensionPath . 'Classes/Tca/Form/Suggest.php',
	'tx_igldapssoauth_typo3_group'		=>	$extensionPath . 'Classes/Library/Typo3Group.php',
	'tx_igldapssoauth_typo3_user'		=>	$extensionPath . 'Classes/Library/Typo3User.php',
	'tx_igldapssoauth_utility_debug'	=>	$extensionPath . 'Classes/Utility/Debug.php',
	'tx_igldapssoauth_utility_ldap'		=>	$extensionPath . 'Classes/Utility/Ldap.php',
	'tx_igldapssoauth_utility_notification' => $extensionPath . 'Classes/Utility/Notification.php',
	'tx_igldapssoauth_sv1'				=>	$extensionPath . 'Classes/Service/Sv1.php',
);

if (version_compare(TYPO3_version, '6.0.0', '<')) {
	if (t3lib_extMgm::isLoaded('rsaauth')) {
		// RSA authentication Classes
		$autoload['tx_rsaauth_backendfactory'] = t3lib_extMgm::extPath('rsaauth') . 'sv1/backends/class.tx_rsaauth_backendfactory.php';
		$autoload['tx_rsaauth_storagefactory'] = t3lib_extMgm::extPath('rsaauth') . 'sv1/storage/class.tx_rsaauth_storagefactory.php';
	}
}

return $autoload;

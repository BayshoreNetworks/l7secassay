<?php

define( 'DVWA_WEB_PAGE_TO_ROOT', '../../' );
require_once DVWA_WEB_PAGE_TO_ROOT.'dvwa/includes/dvwaPage.inc.php';

dvwaPageStartup( array( 'authenticated', 'phpids' ) );

$page = dvwaPageNewGrab();
$page[ 'title' ] .= $page[ 'title_separator' ].'Vulnerability: SQL Injection';
$page[ 'page_id' ] = 'sqli';

dvwaDatabaseConnect();

$vulnerabilityFile = '';
switch( $_COOKIE[ 'security' ] ) {
	case 'low':
		$vulnerabilityFile = 'low.php';
		break;

	case 'medium':
		$vulnerabilityFile = 'medium.php';
		break;

	case 'high':
	default:
		$vulnerabilityFile = 'high.php';
		break;
}

require_once DVWA_WEB_PAGE_TO_ROOT."vulnerabilities/sqli/source/{$vulnerabilityFile}";

$page[ 'help_button' ] = 'sqli';
$page[ 'source_button' ] = 'sqli';

$magicQuotesWarningHtml = '';

// Check if Magic Quotes are on or off
if( ini_get( 'magic_quotes_gpc' ) == true ) {
	$magicQuotesWarningHtml = "	<div class=\"warning\">Magic Quotes are on, you will not be able to inject SQL.</div>";
}

$page[ 'body' ] .= "
<div class=\"body_padded\">
	<h1>Vulnerability: SQL Injection</h1>

	{$magicQuotesWarningHtml}

	<div class=\"vulnerable_code_area\">

		<h3>User ID:</h3>

		<form action=\"#\" method=\"GET\">
			<input type=\"text\" name=\"id\">
			<input type=\"submit\" name=\"Submit\" value=\"Submit\">
		</form>

		{$html}

	</div>

	<h2>More info</h2>
	<ul>
		<li>".dvwaExternalLinkUrlGet( 'http://www.securiteam.com/securityreviews/5DP0N1P76E.html')."</li>
		<li>".dvwaExternalLinkUrlGet( 'http://en.wikipedia.org/wiki/SQL_injection')."</li>
		<li>".dvwaExternalLinkUrlGet( 'http://www.unixwiz.net/techtips/sql-injection.html')."</li>
	</ul>
</div>
";

dvwaHtmlEcho( $page );

?>
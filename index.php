<?php

require __DIR__ . '/config.php';
require __DIR__ . '/vendor/autoload.php';
require __DIR__ . '/discordHelperClass.php';

session_start();

#########################
#testing OAuth user stuff
#########################
$provider = new \Wohali\OAuth2\Client\Provider\Discord([
    'clientId' => CLIENT_ID,
    'clientSecret' => CLIENT_SECRET,
    'redirectUri' => REDIRECT_URI
]);

$options = [
    'state' => 'OPTIONAL_CUSTOM_CONFIGURED_STATE',
    'scope' => ['identify', 'guilds'] // array or string
];

if (!isset($_GET['code'])) {
    
    // Step 1. Get authorization code
    $authUrl = $provider->getAuthorizationUrl($options);
    $_SESSION['oauth2state'] = $provider->getState();
    header('Location: ' . $authUrl);

// Check given state against previously stored one to mitigate CSRF attack
} elseif (empty($_GET['state']) || ($_GET['state'] !== $_SESSION['oauth2state'])) {

    unset($_SESSION['oauth2state']);
    exit('Invalid state');

} else {

    // Step 2. Get an access token using the provided authorization code
    $token = $provider->getAccessToken('authorization_code', [
        'code' => $_GET['code']
    ]);

    // testing
    #echo '<h2>Token details:</h2>';
    #echo 'Token: ' . $token->getToken() . "<br/>";
    #echo 'Refresh token: ' . $token->getRefreshToken() . "<br/>";
    #echo 'Expires: ' . $token->getExpires() . " - ";
    #echo ($token->hasExpired() ? 'expired' : 'not expired') . "<br/>";


    try {
        #set this to see their guilds instead of user info
        #$provider->setResourceUrl("/users/@me/guilds");
        $user = $provider->getResourceOwner($token);
        #echo '<h2>Resource owner details:</h2>';
        #printf('Hello %s#%s!<br/><br/>', $user->getUsername(), $user->getDiscriminator());
        #var_export($user->toArray());

    } catch (Exception $e) {

        // Failed to get user details
        exit('Failed to get user details from Discord.');

    }
}



###################
#testing bot stuff
###################

echo "<html>";

$discordHelperClass = new discordHelperClass();
use RestCord\DiscordClient;


$discord = new DiscordClient(['token' => BOT_TOKEN]); // Token is required

#get all the roles in the guild
$roles_array = $discord->guild->getGuildRoles(['guild.id' => intval(RCHAIN_GUILD_ID)]);

#Find the required role name, and get its id
$role_id_required = $discordHelperClass->getRoleIdFromString($roles_array, DISCORD_COOP_ROLE);

#Get a list of members, along with their role id's
$guild_members = $discord->guild->listGuildMembers(['guild.id' => intval(RCHAIN_GUILD_ID), 'limit' => 1000]);

#get the roles of the authorized member/user
$user_roles = $discordHelperClass->getRolesOfUser($guild_members, $user->getUsername(), $user->getDiscriminator());

echo "<br>role id's that the authenticated user has<br>";
print_r($user_roles);
echo "<br>required role id = ".$role_id_required . "<br>";


#now check the member has the required role
$is_user_coop_member = $discordHelperClass->checkIfUserHasRoleId($user_roles, $role_id_required);

if($is_user_coop_member == true)
{
    echo "user is valid";
}
else
{
    echo "user is invalid";
}

echo "</html>";

?>

package Kernel::Config;
use strict;
use warnings;
use utf8;
sub Load {
  my $Self = shift;

    # Agent Authentication and Authorization by Shibboleth
    $Self->{'AuthModule'} = 'Kernel::System::Auth::HTTPBasicAuthShib';

# If you want to use different Shibboleth environments, other then the defaults:
#    $Self->{'User::AuthModule::HTTPBasicAuthShib::MailEnvVar'} = 'mail';
#    $Self->{'User::AuthModule::HTTPBasicAuthShib::FirstNameEnvVar'} = 'givenName';
#    $Self->{'User::AuthModule::HTTPBasicAuthShib::LastNameEnvVar'} = 'sn';
#    $Self->{'User::AuthModule::HTTPBasicAuthShib::displayNameEnvVar'} = 'displayName';
#    $Self->{'User::AuthModule::HTTPBasicAuthShib::EntitlementEnvVar'} = 'entitlement';

# You can use the value of the Entitlement attributes to set the role of the agent. Set the prefix of the Entitlement:
# eg. urn:geant:yourdomain.tld:AA:X:admin;urn:geant:yourdomain.tld:AA:X:stats;urn:geant:yourdomain.tld:AA:X:users   If you set these values to Entitlement attributes, your agent will be in these roles: admin,stats,users.

     $Self->{'User::AuthModule::HTTPBasicAuthShib::groupPrefixVar'} = 'urn:geant:yourdomain.tld:AA:X:';

# If you logout the OTRS will kill the OTRS as well as Shibboleth sessions:
    $Self->{'LogoutURL'} = $ENV{HTTP_SHIB_HANDLER} . "/Logout";
    $Self->{'CustomerPanelLogoutURL'} =  $ENV{HTTP_SHIB_HANDLER} . "/Logout";

  return 1;
}
use Kernel::Config::Defaults; # import Translatable()
use parent qw(Kernel::Config::Defaults);
1;

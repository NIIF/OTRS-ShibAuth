package Kernel::System::Auth::HTTPBasicAuthShib;

use strict;
use warnings;
use Data::Dumper;

our @ObjectDependencies = ( 'Kernel::Config', 'Kernel::System::Log', );

sub new {
    my ( $Type, %Param ) = @_;

    # allocate new hash for object
    my $Self = {};
    bless( $Self, $Type );

    $Self->{UserObject}  = $Kernel::OM->Get('Kernel::System::User');
    $Self->{GroupObject} = $Kernel::OM->Get('Kernel::System::Group');

    $Self->{MailEnvVar} = $Kernel::OM->Get('Kernel::Config')
      ->Get('User::AuthModule::HTTPBasicAuthShib::MailEnvVar') || 'mail';
    $Self->{FirstNameEnvVar} =
      $Kernel::OM->Get('Kernel::Config')
      ->Get('User::AuthModule::HTTPBasicAuthShib::FirstNameEnvVar')
      || 'givenName';
    $Self->{LastNameEnvVar} = $Kernel::OM->Get('Kernel::Config')
      ->Get('User::AuthModule::HTTPBasicAuthShib::LastNameEnvVar') || 'surname';
    $Self->{displayNameEnvVar} =
      $Kernel::OM->Get('Kernel::Config')
      ->Get('User::AuthModule::HTTPBasicAuthShib::displayNameEnvVar')
      || 'displayName';
    $Self->{EntitlementEnvVar} =
      $Kernel::OM->Get('Kernel::Config')
      ->Get('User::AuthModule::HTTPBasicAuthShib::EntitlementEnvVar')
      || 'entitlement';
    $Self->{rolePrefixVar} = $Kernel::OM->Get('Kernel::Config')
      ->Get('User::AuthModule::HTTPBasicAuthShib::rolePrefixVar');

    #$Self->{Debug} = 1;

    $Self->{Count} = $Param{Count} || '';

    return $Self;
}

sub GetOption {
    my ( $Self, %Param ) = @_;

    # module options
    my %Option = ( PreAuth => 1, );

    # return option
    return $Option{ $Param{What} };
}

sub Auth {
    my ( $Self, %Param ) = @_;

    my $User = $ENV{REMOTE_USER} || $ENV{HTTP_REMOTE_USER} || $ENV{HTTP_EPPN};
    my $RemoteAddr = $ENV{REMOTE_ADDR} || 'Got no REMOTE_ADDR env!';
    my $Mail =
         $ENV{ $Self->{MailEnvVar} }
      || $ENV{HTTP_MAIL}
      || 'invalid_email@noreply.com';
    my $displayName =
         $ENV{ $Self->{displayNameEnvVar} }
      || $ENV{HTTP_DISPLAYNAME}
      || 'display name';
    my $FirstName =
         $ENV{ $Self->{FirstNameEnvVar} }
      || $ENV{HTTP_GIVENNAME}
      || @{ [ $displayName =~ m/[^\s]+/g ] }[1]
      || 'first_name';
    my $LastName =
         $ENV{ $Self->{LastNameEnvVar} }
      || $ENV{HTTP_SURNAME}
      || @{ [ $displayName =~ m/[^\s]+/g ] }[0]
      || 'last_name';
    my $rolePrefix = $Self->{rolePrefixVar};
    my @shibRoles =
      ( $ENV{ $Self->{EntitlementEnvVar} } =~ /$rolePrefix([^;]*)/g );

    my $UserID;

    if ( !$User ) {
        $Kernel::OM->Get('Kernel::System::Log')->Log(
            Priority => 'notice',
            Message => "User: No \$ENV{REMOTE_USER} or \$ENV{HTTP_REMOTE_USER} !(REMOTE_ADDR: $RemoteAddr): " . $ENV{HTTP_EPPN},
        );
        return;
    }

    my $ConfigObject = $Kernel::OM->Get('Kernel::Config');

    my $Replace =
      $ConfigObject->Get( 'AuthModule::HTTPBasicAuth::Replace' . $Self->{Count}, );
    if ($Replace) {
        $User =~ s/^\Q$Replace\E//;
    }

    my $ReplaceRegExp = $ConfigObject->Get('AuthModule::HTTPBasicAuth::ReplaceRegExp' . $Self->{Count},);
    if ($ReplaceRegExp) {
        $User =~ s/$ReplaceRegExp/$1/;
    }

    # Apache Environments Debug Log
    if ( $Self->{Debug} > 0 ) {
        $Kernel::OM->Get('Kernel::System::Log')->Log(
            Priority => 'debug',
            Message  => 'Apache environment vars:'
        );
        foreach my $var ( sort keys %ENV ) {
            $Kernel::OM->Get('Kernel::System::Log')->Log(
                Priority => 'debug',
                Message  => $var . "=" . $ENV{$var},
            );
        }
    }

    # Create new agent
    my %UserTest = $Self->{UserObject}->GetUserData( User => $User );
    if ( !%UserTest ) {
        $Kernel::OM->Get('Kernel::System::Log')->Log(
            Priority => 'notice',
            Message => "User $User doesn't have an account here yet, provisioning it now",
        );

        $UserID = $Self->{UserObject}->UserAdd(
            UserFirstname => $FirstName,
            UserLastname  => $LastName,
            UserLogin     => $User,
            UserEmail     => $Mail,
            ValidID       => 1,
            ChangeUserID  => 1,
        );

    }
    else {

        my %User = $Self->{UserObject}->GetUserData(
            User  => $User,
            Valid => 1,
        );

        $UserID = $User{'UserID'};

        # Update of Agent details
        if ( $User{'UserEmail'} ne $Mail ) {
            if ( $Self->{Debug} > 0 ) {

                $Kernel::OM->Get('Kernel::System::Log')->Log(
                    Priority => 'debug',
                    Message  => "Current email address of " . $User . ": " . $User{'UserEmail'},
                );
            }

            if (
                $Self->{UserObject}->UserUpdate(
                    UserID        => $UserID,
                    UserFirstname => $FirstName,
                    UserLastname  => $LastName,
                    UserLogin     => $User,
                    UserEmail     => $Mail,
                    ValidID       => 1,
                    ChangeUserID  => 1,
                )
              )
            {
                $Kernel::OM->Get('Kernel::System::Log')->Log(
                    Priority => 'info',
                    Message  => "Changed the email of " . $User . " to " . $Mail
                );
            }

        }

    }

    if ( $Self->{Debug} > 0 ) {
        $Kernel::OM->Get('Kernel::System::Log')->Log(
            Priority => 'debug',
            Message  => "shibRoles length: " . scalar(@shibRoles),
        );
    }

    # Assign agent to proper roles
    if ( scalar(@shibRoles) ) {

        # Get roles of agent
        my %otrsRoles =
          $Self->{GroupObject}->PermissionUserRoleGet( UserID => $UserID, );

        my $shibroleID;
        my $RoleID;
        my $Role;

        # Assign agent to new roles
        foreach $shibroleID (@shibRoles) {

            if ( exists $otrsRoles{$shibroleID} ) {

                if ( $Self->{Debug} > 0 ) {

                    $Role = $Self->{GroupObject}->RoleLookup( 'RoleID' => $shibroleID );

                    $Kernel::OM->Get('Kernel::System::Log')->Log(
                        Priority => 'debug',
                        Message  => "$User member of $Role role",
                    );
                }

            }
            else

            {

                if (
                    $Self->{GroupObject}->PermissionRoleUserAdd(
                        RID    => $shibroleID,
                        UID    => $UserID,
                        Active => 1,
                        UserID => 1,
                    )
                  )

                {

                    $Role = $Self->{GroupObject}->RoleLookup( 'RoleID' => $shibroleID );

                    $Kernel::OM->Get('Kernel::System::Log')->Log(
                        Priority => 'info',
                        Message  => "Added $User to $Role role",
                    );
                }

            }

        }

        # Unassign agent from old roles
        foreach $RoleID ( keys %otrsRoles ) {

            if ( grep { $_ eq $RoleID } @shibRoles ) {

                1;

            }
            else {

                if (
                    $Self->{GroupObject}->PermissionRoleUserAdd(
                        RID    => $RoleID,
                        UID    => $UserID,
                        Active => 0,
                        UserID => 1,
                    )
                  )
                {

                    $Role = $Self->{GroupObject}->RoleLookup( 'RoleID' => $RoleID );

                    $Kernel::OM->Get('Kernel::System::Log')->Log(
                        Priority => 'info',
                        Message  => "Removed $User from $Role role",
                    );
                }

            }

        }
    }

    # log
    $Kernel::OM->Get('Kernel::System::Log')->Log(
        Priority => 'notice',
        Message  => "User: $User authentication ok (REMOTE_ADDR: $RemoteAddr).",
    );

    return $User;
}

1;

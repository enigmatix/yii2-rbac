# yii2-rbac
Helper Class to build your RBAC using easy configuration arrays.

Some quick examples:

Creates a single role with associated permissions.  The default construction is:
     
A role with sub-roles:

                 ['Support',   ['Basic','SupportManager']],
     
A role with permissions:

                 ['UserManager', 'permissions' => ['assumeUserIdentity','resetUserPassword']],
     
A role with a rule:

                 ['Basic', 'ruleName' => 'notGuest']
     
Or an entry with all three:
     
                 ['Support', ['Basic','SupportManager'],
                       'ruleName' => 'notGuest',
                       'permissions' => ['assumeUserIdentity','resetUserPassword']]
     
And then add them via the Rbac Builder:

    RbacBuilder::addRules([
        ['notGuest' => GuestRule::className()]
    ]);
    
    RbacBuilder::createRoles(['Support', ['Basic','SupportManager'],
        'ruleName' => 'notGuest',
        'permissions' => ['assumeUserIdentity','resetUserPassword']
        ]);
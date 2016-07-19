<?php
/**
 * Created by PhpStorm.
 * User: Joel Small
 * Date: 26/02/2016
 * Time: 2:58 PM
 */

namespace enigmatix\yii2rbac;

use yii;
use yii\base\Object;
use yii\base\InvalidConfigException;
use yii\helpers\ArrayHelper;
/**
 * Class RbacBuilder
 * @package enigmatix\yii2rbac
 */
class RbacBuilder extends Object
{

    /**
     * @var yii\rbac\Rule[] container for all custom defined rules that may apply to an object.  These may be reused
     * between roles/rules
     */

    private static $ruleTypes   = [];

    /**
     * @var yii\rbac\Permission[] container for all defined permissions.  These permissions may be reused between
     * roles/rules.
     */

    private static $permissions = [];

    /**
     * @return yii\rbac\ManagerInterface
     */

    static function getAuthManager() {
        return Yii::$app->authManager;
    }

    /**
     * Retrieves an existing role from within the auth manager.  They are not cached locally within this helper class.
     * @param $role
     * @return null|yii\rbac\Role
     */
    static function getRole($role){
        $auth           = static::getAuthManager();
        $retrievedRole  = $auth->getRole($role);

        if($retrievedRole != null){
            return $retrievedRole;
        }else{
            throw new yii\base\InvalidCallException("Role $role has not yet been defined.  The role cannot be retrieved");
        }
    }

    /**
     * Destroys an existing RBAC configuration so as to allow rebuilding from scratch.
     */
    static function initialise(){
        static::getAuthManager()->removeAll();
    }

    /**
     * @param yii\rbac\Rule $model the rule object itself
     * @param string $ruleType name of the associated rule, used when setting a role or permission to execute the rule
     * via the ruleName property.
     */
    static function addRuleType(yii\rbac\Rule $model, $ruleType){
        static::$ruleTypes[$ruleType] = $model;
        $auth = static::getAuthManager();

        $auth->add($model);
    }

    /**
     * @param array[] $types array of rules defined for bulk entry into the RbacBuilder, and on to the auth
     * manager.  These should always be run first as a preparation command.
     */
    static function addRuleTypes(array $types){
        foreach ($types as $type => $model){
            static::addRuleType($model, $type);
        }
    }

    /**
     * @param $name
     * @param null $type
     * @param array $parameters
     * @return mixed
     * @throws InvalidConfigException
     */
    static function addPermission($name, $type = null, $parameters = []){

        if($type != null ){
            if(!array_key_exists($type, static::$ruleTypes)){
                throw new InvalidConfigException("Invalid rule specified.  A rule type of name $type does not exist");
            }
        }

        $auth                       = static::getAuthManager();
        $permission                 = $auth->createPermission($name);
        $permission->description    = $name;
        $permission->ruleName       = $type;

        foreach ($parameters as $prop => $value){
            $permission->$prop = $value;
        }

        $auth->add($permission);

        static::$permissions[$name] = $permission;

        return static::$permissions[$name];
    }

    /**
     * @param array $rules adds multiple rules at once
     */
    static function addRules(array $rules){


        foreach ($rules as $rule){
            static::addRule($rule);
        }
    }

    /**
     * @param array $rule adds a single rule, requiring a unique rule name.
     */
    static function addRule(array $rule){

        reset($rule);
        $name       = key($rule);
        $class      = array_shift($rule);
        $parameters = count($rule) ? array_shift($rule) : [];

        $ruleObject = new $class;

        foreach ($parameters as $attribute => $value){
            $ruleObject->$attribute = $value;
        }
        static::addRuleType($ruleObject, $name);
    }

    /**
     * @param $role
     * @param array $permissions
     * @throws InvalidConfigException
     */
    static function addPermissions($role, array $permissions){
        $auth       = static::getAuthManager();

        foreach ($permissions as $permission){
            $permission = (array) $permission;
            $name       = array_shift($permission);
            $type       = array_shift($permission);
            $parameters = $permission;


            if(!ArrayHelper::keyExists($name, static::$permissions))
                static::$permissions[$name] = static::addPermission($name, $type, $parameters);
            $auth->addChild($role, static::$permissions[$name]);
        }
    }

    /**
     * Creates a single role with associated permissions.  The default construction is:
     *
     * A role with sub-roles:
     *            ['Support',   ['Basic','SupportManager']],
     *
     * A role with permissions:
     *            ['UserManager', 'permissions' => ['assumeUserIdentity','resetUserPassword']],
     *
     * A role with a rule:
     *            ['Basic', 'ruleName' => 'notGuest']
     *
     * Or an entry with all three:
     *
     *            ['Support', ['Basic','SupportManager'],
     *                  'ruleName' => 'notGuest',
     *                  'permissions' => ['assumeUserIdentity','resetUserPassword']]
     *
     * @param array $roleConfiguration
     * @return null|yii\rbac\Role
     * @throws InvalidConfigException
     */
    static function createRole(array $roleConfiguration){

        $auth               = static::getAuthManager();
        $role               = $roleConfiguration[0];
        $inherits           = ArrayHelper::getValue($roleConfiguration, 1, false);

        try{
            $permissions        = ArrayHelper::getValue($roleConfiguration,'permissions', false);
            $rule               = ArrayHelper::getValue($roleConfiguration, 'ruleName');
            $newRole = $auth->getRole($role);

            if($newRole == null){
                $newRole = $auth->createRole($role);
                $newRole->ruleName = $rule;
                $auth->add($newRole);
            }
            if($permissions)
                static::addPermissions($newRole, (array) $permissions);

        }catch(\Exception $e){
            throw new InvalidConfigException("Incorrect role configuration for $role.  Permission or role incorrectly defined." . $e->getMessage());
        }

        if($inherits){
            static::applyInheritance($role,(array) $inherits);
        }
        return $newRole;
    }

    /**
     * Sets parent/child relationships for roles.  If the child object has not yet been created, the process will
     * create the child role for you.  In this way, you do not need to worry about the order of defining roles and inheritance
     *
     * @param $role
     * @param array $inheritance
     * @throws InvalidConfigException
     */
    protected static function applyInheritance($role, array $inheritance){

        $auth   = static::getAuthManager();
        $parent = $auth->getRole($role);

        foreach ($inheritance as $inherits){

            try{
                $child = $auth->getRole($inherits);
                if($child == null){
                    $child = static::createRole((array) $inherits);
                }
            }catch(\Exception $e){
                throw new InvalidConfigException("Invalid inheritance configuration for role $role.  Inheritance array may contain invalid sub-arrays");
            }

            $auth->addChild($parent, $child);

        }

    }

    /**
     * @param array $roles
     * @throws InvalidConfigException
     */
    static function createRoles(array $roles){
        foreach ($roles as $role){
            static::createRole($role);
        }
    }
}
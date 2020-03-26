import unittest
from permissions_package.permissions import AccessControl, ActionType, User, Role

normal_role = Role('normal_user')
admin_role = Role('admin')


normal_user = User(normal_role.get_name(), roles=[normal_role])
admin_user = User(admin_role.get_name(), roles=[admin_role, normal_role])


acl = AccessControl()

acl.add_role(admin_role.get_name())
acl.add_role(normal_role.get_name())

acl.add_resource('resource1')
acl.add_resource('resource2')

acl.add_rule(ActionType.READ, normal_role.get_name(), 'resource1')
acl.add_rule(ActionType.DELETE, admin_role.get_name(), 'resource2')



class TestPermissions(unittest.TestCase):

    def test_read_rule_everyone(self):
        """checking resource access with the employee himself in context
        """
        for user_role in [role.get_name() for role in normal_user.get_roles()]:
            assert acl.is_action_allowed(ActionType.READ, user_role, 'resource1') == True

    def test_write_rule_everyone(self):
        """write operation by the role 'everyone' should fail
        """
        for user_role in [role.get_name() for role in normal_user.get_roles()]:
            assert acl.is_action_allowed(ActionType.WRITE, user_role, 'resource1') == False

    def test_delete_rule_admin(self):
        """admin role should be able to read
        """
        for user_role in [role.get_name() for role in normal_user.get_roles()]:
            if user_role == 'admin':
                assert acl.is_action_allowed(ActionType.DELETE, user_role, 'resource2') == True
            else:
                assert acl.is_action_allowed(ActionType.DELETE, user_role, 'resource2') == False

    def test_role_assignment(self):
        """Creates the roles which need to be assigned to users
        """
        assert [role.get_name() for role in normal_user.get_roles()] == ['normal_user']
        assert [role.get_name() for role in admin_user.get_roles()].sort() == ['admin', 'normal_user'].sort()

    def test_delete_role_from_user(self):
        """Tests the function to delete a role from a user
        """
        anonymous_user = User('anonymous_user', roles=[normal_role, admin_role])
        anonymous_user.remove_role('admin')
        assert 'admin' not in [role.get_name() for role in anonymous_user.get_roles()]

    def test_delete_user(self):
        """Tests successful deletion of user
        """
        unwanted_user = User('unwanted_user', roles=[normal_role])
        del unwanted_user
        assert 'unwanted_user' not in dir()


if __name__ == '__main__':
    unittest.main()

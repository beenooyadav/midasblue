"""
    Role Based Access Control:
"""
from enum import Enum


class ActionType(Enum):
    READ = 'read'
    WRITE = 'write'
    DELETE = 'delete'


class AccessControl(object):
    """Defines the detailed access control rules
    """

    def __init__(self):
        self.roles = []
        self.resources = []
        self._read = []
        self._write = []
        self._delete = []
        self.ACTION_DICT = {
            ActionType.READ: self._read,
            ActionType.WRITE: self._write,
            ActionType.DELETE: self._delete
        }

    def validate(self, role, resource):
        access = True
        if role not in self.roles:
            access = False
        if resource not in self.resources:
            access = False

        return access

    def add_role(self, role):
        self.roles.append(role)

    def get_roles(self):
        for role in self.roles:
            yield role

    def remove_role(self, role_name):
        for role in self.get_roles():
            if role == role_name:
                self.roles.remove(role)

    def add_resource(self, resource):
        self.resources.append(resource)

    def get_resources(self):
        for resource in self.resources:
            yield resource

    def remove_resource(self, resource):
        for resource in self.get_resources():
            if resource == resource:
                self.resources.remove(resource)

    def add_rule(self, action_type, role, resource):
        """Add rules to allow action_type access

        :param action_type: ActionType
        :param role: Role of this rule
        :param resource: The resource in question
        """

        if not self.validate(role, resource):
            return
        permission = (role, resource)
        if permission not in self.ACTION_DICT.get(action_type):
            self.ACTION_DICT.get(action_type).append(permission)

    def is_action_allowed(self, action_type, role, resource):
        """returns whether the role is allowed action_type access resource
               :return: Boolean
               """
        if not self.validate(role, resource):
            return False
        return (role, resource) in self.ACTION_DICT.get(action_type)


class Role(object):
    """Role will be associated to permissions to access resources

    :param name: the name of the role
    """

    def __init__(self, name):
        """Initializes the a role.

        """
        self.name = name

    def get_name(self):
        """returns the name of the role
        """
        return self.name

    def __repr__(self):
        return f'<Role {self.name}>'


class User(object):
    """User is associated with one or more roles
    """

    def __init__(self, name, roles=None):
        """Initialises the roles assigned to the user

        :type name: name of user
        :param roles: <list> object which holds the roles assigned to the user
        """
        self.name = name
        if roles is None:
            roles = []
        self.roles = roles

    def add_role(self, role):
        self.roles.append(role)

    def get_roles(self):
        for role in self.roles:
            yield role

    def remove_role(self, role_name):
        """Remove a role assigned to a User

        :param role_name: name of the role which needs to be removed
        """
        for role in self.get_roles():
            if role.get_name() == role_name:
                self.roles.remove(role)

    def __repr__(self):
        return f'<User {self.name} {self.roles}>'

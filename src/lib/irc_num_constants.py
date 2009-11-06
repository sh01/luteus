#!/usr/bin/env python
#Copyright 2009 Sebastian Hagen
# This file is part of luteus.
#
# luteus is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# luteus is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with luteus.  If not, see <http://www.gnu.org/licenses/>.

def __add_numeric(num, name):
   globals()[name] = num

__NUM_specs = (
   (263, 'RPL_TRYAGAIN'),
   
   (311, 'RPL_WHOISUSER'),
   (312, 'RPL_WHOISSERVER'),
   (313, 'RPL_WHOISOPERATOR'),
   (314, 'RPL_WHOWASUSER'),
   (317, 'RPL_WHOISIDLE'),
   (318, 'RPL_ENDOFWHOIS'),
   (319, 'RPL_WHOISCHANNELS'),
   
   (321, 'RPL_LISTSTART'),
   (322, 'RPL_LIST'),
   (323, 'RPL_LISTEND'),
   
   (331, 'RPL_NOTOPIC'),
   (332, 'RPL_TOPIC'),
   (353, 'RPL_NAMREPLY'),
   (366, 'RPL_ENDOFNAMES'),
   (324, 'RPL_CHANNELMODEIS'),
   
   (364, 'RPL_LINKS'),
   (365, 'RPL_ENDOFLINKS'),
   
   (369, 'RPL_ENDOFWHOWAS'),
   # Errors
   (401, 'ERR_NOSUCHNICK'),
   (402, 'ERR_NOSUCHSERVER'),
   (403, 'ERR_NOSUCHCHANNEL'),
   (404, 'ERR_CANNOTSENDTOCHAN'),
   (405, 'ERR_TOOMANYCHANNELS'),
   (406, 'ERR_WASNOSUCHNICK'),
   (407, 'ERR_TOOMANYTARGETS'),
   (409, 'ERR_NOORIGIN'),
   (421, 'ERR_UNKNOWNCOMMAND'),
   (431, 'ERR_NONICKNAMEGIVEN'),
   
   # pre-reg stuff
   (432, 'ERR_ERRONEUSNICKNAME'),
   (433, 'ERR_NICKNAMEINUSE'),
   (436, 'ERR_NICKCOLLISION'),
   (437, 'ERR_UNAVAILRESOURCE'),
   (451, 'ERR_NOTREGISTERED'),
   
   (462, 'ERR_ALREADYREGISTRED'),
   
   (481, 'ERR_NOPRIVILEGES'),
   (484, 'ERR_RESTRICTED')
)

for (num, name) in __NUM_specs:
   __add_numeric(num, name)
   

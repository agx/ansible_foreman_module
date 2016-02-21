A simple module to create hosts in [the Foreman][] via [Ansible][]

Usage:

    ansible-playbook --module-path . -c local -i localhost, example.yml

The file example.yml has an example. You can augment this with a
custom json template for parameters that aren't configurable (yet).

Simple example:

    - foremanhost: name=foo hostgroup=bar state=present api_user=foreman api_password=changeme api_url: https://127.0.0.1

[the Foreman]: http://theforeman.org
[Ansible]: http://ansible.com
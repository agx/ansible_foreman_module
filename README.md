A simple module to create image based VMs in [the Foreman][] via [Ansible][]

For setting up Foreman itself check out the excellent [ansible-module-foreman][].

Usage:

    ansible-playbook --module-path . -c local -i localhost, example.yml

The file [example.yml][] has an example.

[the Foreman]: http://theforeman.org
[Ansible]: http://ansible.com
[ansible-module-foreman]: https://github.com/Nosmoht/ansible-module-foreman

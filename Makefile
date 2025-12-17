.PHONY: lint ansible-check run-linux run-windows cleanup

lint:
	bash -n scripts/linux/*.sh
	pwsh -NoLogo -NoProfile -Command "Get-ChildItem scripts/windows/*.ps1 | ForEach-Object { powershell -NoLogo -NoProfile -Command \"Set-StrictMode -Version Latest; . $_\" }"

ansible-check:
	ansible-playbook ansible/playbooks/linux-ttp.yml --syntax-check
	ansible-playbook ansible/playbooks/windows-ttp.yml --syntax-check

run-linux:
	ansible-playbook -i ansible/inventory/hosts ansible/playbooks/linux-ttp.yml

run-windows:
	ansible-playbook -i ansible/inventory/hosts ansible/playbooks/windows-ttp.yml

cleanup:
	ansible-playbook -i ansible/inventory/hosts ansible/playbooks/cleanup.yml

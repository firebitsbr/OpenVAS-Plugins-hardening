# script_id 99179
# plugin_id STRG-1846
# Wed 25 May 2011 01:02:13 PM BRT
# Mauro Risonho de Paula Assumpção
# Pentester/Analista em Segurança
# mauro.risonho@gmail.com

if(description)
{
script_id(99179);
script_copyright("Este script é Copyleft 2011 GNU 3");

script_version("1.0");
name["english"] = "STRG-1846-Linux - Checking USB storage driver in directory /etc/modprobe.d and configuration file /etc/modprobe.conf";
desc["english"] = "Este script faz login na máquina remota e Checking USB storage driver in directory /etc/modprobe.d and configuration file /etc/modprobe.conf.
Risk factor: Nenhum";
script_description(english:desc["english"]);
script_name(english:name["english"]);
family["english"] = "firebits-STRG-Security";

script_family(english:family["english"]);
summary["english"] = "Este script faz login na máquina remota e Checking USB storage driver in directory /etc/modprobe.d and configuration file /etc/modprobe.conf";
script_summary(english:summary["english"]);
script_dependencie("find_service2.nasl");
script_category(ACT_INIT);
exit(0);
}
 
include("misc_func.inc");
include("ssh_func.inc");
include("global_settings.inc");
 
account = "teste";
password = "123";

display("login remoto\n");
 

soc = open_sock_tcp(22);
if ( soc )
{

	ret = ssh_login(socket:soc, login:account, password:password);

	display("Checking firewire storage driver in directory /etc/modprobe.d and configuration file /etc/modprobe.conf\n");
	cmd000=ssh_cmd(socket:soc, cmd:"cat /etc/modprobe.d | egrep "blacklist (ohci1394|firewire-ohci)" /etc/modprobe.d | grep "ohci" | grep -v "#"");	
	cmd001=ssh_cmd(socket:soc, cmd:"cat /etc/modprobe.d | egrep "install (ohci1394|firewire-ohci) /bin/true" /etc/modprobe.d | grep "ohci" | grep -v "#"");	

	display(cmd000);	
	display(cmd001);	

	close(soc);	
	
	}

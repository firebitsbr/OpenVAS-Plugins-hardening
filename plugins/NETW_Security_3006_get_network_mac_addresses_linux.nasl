# script_id 99982
# plugin_id NETW-3006
# Wed 25 May 2011 01:02:13 PM BRT
# Mauro Risonho de Paula Assumpção
# Pentester/Analista em Segurança
# mauro.risonho@gmail.com

if(description)
{
script_id(99982);
script_copyright("Este script é Copyleft 2011 GNU 3");

script_version("1.0");
name["english"] = "NETW-3006-Linux - Get network MAC addresses";
desc["english"] = "Este script faz login na máquina remota e verifica do(s) MAC ADDRESS da(s) placa(s) de rede.
Risk factor: Nenhum";
script_description(english:desc["english"]);
script_name(english:name["english"]);
family["english"] = "firebits-Rede";

script_family(english:family["english"]);
summary["english"] = "Este script faz login na máquina remota e verifica do(s) MAC ADDRESS da(s) placa(s) de rede";
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

#/etc/motd

display("login remoto\n");
 

soc = open_sock_tcp(22);
if ( soc )
{

	ret = ssh_login(socket:soc, login:account, password:password);
	cmd000=ssh_cmd(socket:soc , cmd:"ifconfig -a | grep 'HWaddr' | awk '{ if ($4=='HWaddr') print $5 }' | sort | uniq");
	display(cmd000);
	close(soc);	
	
	}

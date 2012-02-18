# plugin_id AUTH-9308
# script_id 99446
# Wed 25 May 2011 01:02:13 PM BRT
# Mauro Risonho de Paula Assumpção
# Pentester/Analista em Segurança
# mauro.risonho@gmail.com

if(description)
{
script_id(99446);
script_copyright("Este script é Copyleft 2011 GNU 3");

script_version("1.0");
name["english"] = "AUTH-9308-Linux - Verificando single user login configuration";
desc["english"] = "Este script faz login na máquina remota e Verificando single user login configuration.
Risk Factor: High";
script_description(english:desc["english"]);
script_name(english:name["english"]);
family["english"] = "firebits-Strong";

script_family(english:family["english"]);
summary["english"] = "Este script faz login na máquina remota e Verificando single user login configuration";
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

	display("Verificando single user login configuration\n");
	cmd000=ssh_cmd(socket:soc, cmd:"cat /etc/inittab | grep "^~~:S:wait:/sbin/sulogin" /etc/inittab");	

	display(cmd000);	
	close(soc);	
	
	}

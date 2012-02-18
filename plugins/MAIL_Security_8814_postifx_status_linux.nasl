# plugin_id MAIL-8814
# script_id 99801
# Wed 25 May 2011 01:02:13 PM BRT
# Mauro Risonho de Paula Assumpção
# Pentester/Analista em Segurança
# mauro.risonho@gmail.com

if(description)
{
script_id(99801);
script_copyright("Este script é Copyleft 2011 GNU 3");

script_version("1.0");
name["english"] = "MAIL-8814-Linux - Verificar daemon Postfix.";
desc["english"] = "Este script faz login na máquina remota e verifica daemon Postfix.
Risk Factor: High";
script_description(english:desc["english"]);
script_name(english:name["english"]);
family["english"] = "firebits-MAIL";

script_family(english:family["english"]);
summary["english"] = "Este script faz login na máquina remota e verifica daemon Postfix.";
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

	display("daemon Postfix em execução\n");
	cmd000=ssh_cmd(socket:soc, cmd:"postfix check");	

	display(cmd000);	
	close(soc);	
	
	}

# plugin_id FINT-4350
# script_id 99011
# Wed 25 May 2011 01:02:13 PM BRT
# Mauro Risonho de Paula Assumpção
# Pentester/Analista em Segurança
# mauro.risonho@gmail.com

if(description)
{
script_id(99011);
script_copyright("Este script é Copyleft 2011 GNU 3");

script_version("1.0");
name["english"] = "FINT-4350-Linux - Verificar por daemon Verificador de Integridade de filesystems.";
desc["english"] = "Este script faz login na máquina remota e verificar daemon Verificador de Integridade de filesystems.
Risk Factor: High";
script_description(english:desc["english"]);
script_name(english:name["english"]);
family["english"] = "firebits-AUTHENTICATION";

script_family(english:family["english"]);
summary["english"] = "Este script faz login na máquina remota e verificar daemon Verificador de Integridade de filesystems.";
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

	cmd000=ssh_cmd(socket:soc, cmd:"ls /usr/sbin/tripwire");	
	cmd001=ssh_cmd(socket:soc, cmd:"ls /usr/sbin/aide");

	display("Exibindo evidência(s) de daemon Verificador de Integridade de filesystems.\n");
	display(cmd000);
	display(cmd001);

	close(soc);	
	
	}

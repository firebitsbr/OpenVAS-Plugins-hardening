# plugin_id FILE-6310
# script_id 99756
# Wed 25 May 2011 01:02:13 PM BRT
# Mauro Risonho de Paula Assumpção
# Pentester/Analista em Segurança
# mauro.risonho@gmail.com

if(description)
{
script_id(99756);
script_copyright("Este script é Copyleft 2011 GNU 3");

script_version("1.0");
name["english"] = "FILE-6310-Linux - Verificar por partições /tmp /home se estão separadas de /.";
desc["english"] = "Este script faz login na máquina remota, obtem RPM package based systems
Risk Factor: High";
script_description(english:desc["english"]);
script_name(english:name["english"]);
family["english"] = "firebits-Packages";

script_family(english:family["english"]);
summary["english"] = "Este script faz login na máquina remota e verifica partições /tmp /home se estão separadas de /";
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

	cmd000=ssh_cmd(socket:soc, cmd:"mount | grep /tmp");	

	display("Verificar por partição /tmp separada do /.\n");
	display(cmd000);

	cmd001=ssh_cmd(socket:soc, cmd:"mount | grep /home");	

	display("Verificar por partição /home separada do /.\n");
	display(cmd001);

	close(soc);	
	
	}

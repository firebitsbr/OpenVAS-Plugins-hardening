# plugin_id DBS-1842
# script_id 99944
# Wed 25 May 2011 01:02:13 PM BRT
# Mauro Risonho de Paula Assumpção
# Pentester/Analista em Segurança
# mauro.risonho@gmail.com

if(description)
{
script_id(99944);
script_copyright("Este script é Copyleft 2011 GNU 3");

script_version("1.0");
name["english"] = "DBS-1842-Linux - Verificar presença do daemon smon: Oracle system monitor";
desc["english"] = "Este script faz login na máquina remota e verifica a presença do daemon smon: Oracle system monitor.
Risk Factor: High";
script_description(english:desc["english"]);
script_name(english:name["english"]);
family["english"] = "firebits-Database";

script_family(english:family["english"]);
summary["english"] = "Este script faz login na máquina remota e verifica a presença do daemon smon: Oracle system monitor";
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

	display("Daemon smon: Oracle system monitor em execução\n");
	cmd000=ssh_cmd(socket:soc, cmd:"ps ax | grep 'smon' | grep -v 'grep'");	

	display(cmd000);	
	close(soc);	
	
	}
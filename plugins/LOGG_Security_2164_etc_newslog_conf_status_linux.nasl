# script_id 99199
# plugin_id LOGG-2164
# Wed 25 May 2011 01:02:13 PM BRT
# Mauro Risonho de Paula Assumpção
# Pentester/Analista em Segurança
# mauro.risonho@gmail.com

if(description)
{
script_id(99200);
script_copyright("Este script é Copyleft 2011 GNU 3");

script_version("1.0");
name["english"] = "LOGG-2164-Linux - Verificar for files in /etc/newsyslog.conf";
desc["english"] = "Este script faz login na máquina remota e Verificar for files in /etc/newsyslog.conf
Risk Factor: High";
script_description(english:desc["english"]);
script_name(english:name["english"]);
family["english"] = "firebits-LOGGING";

script_family(english:family["english"]);
summary["english"] = "Este script faz login na máquina remota e Verificar for files in /etc/newsyslog.conf";
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

	display("Verificar for files in /etc/newsyslog.conf\n");
	cmd000=ssh_cmd(socket:soc, cmd:"cat /etc/newsyslog.conf | sort | uniq | grep "^/" | awk '{ print $1 }'");	

	display(cmd000);

	close(soc);	
	
	}

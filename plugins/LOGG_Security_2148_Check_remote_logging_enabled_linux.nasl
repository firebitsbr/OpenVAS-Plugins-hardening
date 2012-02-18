# plugin_id LOGG-2148
# script_id 99202
# Wed 25 May 2011 01:02:13 PM BRT
# Mauro Risonho de Paula Assumpção
# Pentester/Analista em Segurança
# mauro.risonho@gmail.com

if(description)
{
script_id(99202);
script_copyright("Este script é Copyleft 2011 GNU 3");

script_version("1.0");
name["english"] = "LOGG-2148-Linux - Check to see if remote logging is enabled";
desc["english"] = "Este script faz login na máquina remota e Check to see if remote logging is enabled
Risk Factor: High";
script_description(english:desc["english"]);
script_name(english:name["english"]);
family["english"] = "firebits-LOGGING";

script_family(english:family["english"]);
summary["english"] = "Este script faz login na máquina remota e Check to see if remote logging is enabled";
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

	display("Check to see if remote logging is enabled\n");
	cmd000=ssh_cmd(socket:soc, cmd:"cat /etc/syslog-ng/syslog-ng.conf | egrep "@[a-zA-Z0-9]" ${SYSLOGD_CONF} | grep -v "^#" | grep -v "[a-zA-Z0-9]@");	

	display(cmd000);

	close(soc);	
	
	}

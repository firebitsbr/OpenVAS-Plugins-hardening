# plugin_id LOGG-2164
# script_id 99198
# Wed 25 May 2011 01:02:13 PM BRT
# Mauro Risonho de Paula Assumpção
# Pentester/Analista em Segurança
# mauro.risonho@gmail.com

if(description)
{
script_id(99200);
script_copyright("Este script é Copyleft 2011 GNU 3");

script_version("1.0");
name["english"] = "LOGG-2164-Linux - Checking deleted files";
desc["english"] = "Este script faz login na máquina remota e Checking deleted files
Risk Factor: Medium";
script_description(english:desc["english"]);
script_name(english:name["english"]);
family["english"] = "firebits-LOGGING";

script_family(english:family["english"]);
summary["english"] = "Este script faz login na máquina remota e Checking deleted files";
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

	display("Checking deleted files\n");
	cmd000=ssh_cmd(socket:soc, cmd:"lsof +L 1 | awk '{ if ($5=="REG") { print $10 } }'");	

	display(cmd000);

	close(soc);	
	
	}

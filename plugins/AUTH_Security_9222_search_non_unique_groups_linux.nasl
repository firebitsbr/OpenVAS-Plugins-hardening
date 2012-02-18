# plugin_id AUTH-9222
# script_id 99913
# Wed 25 May 2011 01:02:13 PM BRT
# Mauro Risonho de Paula Assumpção
# Pentester/Analista em Segurança
# mauro.risonho@gmail.com

if(description)
{
script_id(99913);
script_copyright("Este script é Copyleft 2011 GNU 3");

script_version("1.0");
name["english"] = "AUTH-9222-Linux - Verificar non unique groups.";
desc["english"] = "Este script faz login na máquina remota e verificar non unique groups.
Risk Factor: Medium";
script_description(english:desc["english"]);
script_name(english:name["english"]);
family["english"] = "firebits-Kernel";

script_family(english:family["english"]);
summary["english"] = "Este script faz login na máquina remota e verificar non unique groups.";
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

	cmd000=ssh_cmd(socket:soc, cmd:"cat /etc/group | grep -v '^#' | grep -v '^$' | awk -F: '{ print $3 }' | sort | uniq -d'");	

	display("Exibindo evidência(s) de non unique groups\n");
	display(cmd000);

	close(soc);	
	
	}


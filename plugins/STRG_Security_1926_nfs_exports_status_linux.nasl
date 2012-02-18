# script_id 99545
# plugin_id STRG-1926
# Wed 25 May 2011 01:02:13 PM BRT
# Mauro Risonho de Paula Assumpção
# Pentester/Analista em Segurança
# mauro.risonho@gmail.com

if(description)
{
script_id(99545);
script_copyright("Este script é Copyleft 2011 GNU 3");

script_version("1.0");
name["english"] = "STRG-1926-Linux - Verificando execução do NFS exports";
desc["english"] = "Este script faz login na máquina remota e Verificando execução do NFS exports.
Risk factor: Nenhum";
script_description(english:desc["english"]);
script_name(english:name["english"]);
family["english"] = "firebits-STRG-Security";

script_family(english:family["english"]);
summary["english"] = "Este script faz login na máquina remota e Verificando execução do NFS exports";
script_summary(english:summary["english"]);
script_dependencie("find_service2.nasl");
script_category(ACT_INIT);
exit(0);
}
 
include("misc_func.inc");
include("ssh_func.inc");
include("global_settings.inc");
 
#account = "root";
#password = "123456";

account = "teste";
password = "123";

display("login remoto\n");
 

soc = open_sock_tcp(22);
if ( soc )
{

	ret = ssh_login(socket:soc, login:account, password:password);

	display("Verificando execução do NFS exports\n");
	cmd000=ssh_cmd(socket:soc, cmd:"cat /etc/exports | grep -v "^$" | grep -v "^#" | sed 's/ /!space!/g'");	

	display(cmd000);	
	close(soc);	
	
	}

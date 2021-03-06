# plugin_id MAIL-8802
# script_id 99195
# Wed 25 May 2011 01:02:13 PM BRT
# Mauro Risonho de Paula Assumpção
# Pentester/Analista em Segurança
# mauro.risonho@gmail.com

if(description)
{
script_id(99200);
script_copyright("Este script é Copyleft 2011 GNU 3");

script_version("1.0");
name["english"] = "MAIL-8802-Linux - Verificar Exim process status";
desc["english"] = "Este script faz login na máquina remota e Verificar Exim process status
Risk Factor: High";
script_description(english:desc["english"]);
script_name(english:name["english"]);
family["english"] = "firebits-MAIL";

script_family(english:family["english"]);
summary["english"] = "Este script faz login na máquina remota e Verificar Exim process status";
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

	display("Verificar Exim process status\n");
	cmd000=ssh_cmd(socket:soc, cmd:"ps ax | grep "/exim" | grep -v "grep"");	

	display(cmd000);

	close(soc);	
	
	}

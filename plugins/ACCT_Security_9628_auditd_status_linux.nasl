# plugin_id ACCT-9628
# script_id 99999
# Wed 25 May 2011 01:02:13 PM BRT
# Mauro Risonho de Paula Assumpção
# Pentester/Analista em Segurança
# mauro.risonho@gmail.com

if(description)
{
script_id(99999);
script_copyright("Este script é Copyleft 2011 GNU 3");
script_author("Mauro Risonho de Paula Assumpção a.k.a firebits");
script_version("1.0");
name["english"] = "ACCT-9628-Linux - Check auditd status";
desc["english"] = "Este script faz login na máquina remota e verifica o status do daemon Auditd.
Risco: Alto";
script_description(english:desc["english"]);
script_name(english:name["english"]);
family["english"] = "firebits-Audit";

script_family(english:family["english"]);
summary["english"] = "Este script faz login na máquina remota e lista os arquivos no diretório";
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
	cmd000=ssh_cmd(socket:soc, cmd:"ps ax | grep 'auditd'|grep -v 'grep'|grep -v 'kauditd'");	
	display(cmd000);	
	close(soc);	
		
	}

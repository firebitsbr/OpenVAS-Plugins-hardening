# script_id 99971
# plugin_id PoC-0001
# Wed 25 May 2011 01:02:13 PM BRT
# Mauro Risonho de Paula Assumpção
# Pentester/Analista em Segurança
# mauro.risonho@gmail.com

if(description)
{
script_id(99971);
script_copyright("Este script é Copyleft 2011 GNU 3");

script_version("1.0");
name["english"] = "PoC-0001-Linux - SSH autenticando login e password via APIs do Knowledge Base";
desc["english"] = "Este script faz login na máquina remota autenticando login e password via APIs do Knowledge Base.
Risk factor: Nenhum";
script_description(english:desc["english"]);
script_name(english:name["english"]);
family["english"] = "firebits-TEST";

script_family(english:family["english"]);
summary["english"] = "Este script faz login na máquina remota autenticando login e password via APIs do Knowledge Base";
script_summary(english:summary["english"]);
script_dependencie("find_service2.nasl");
script_dependencie("ssh_authorization.nasl");
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


#/etc/motd

display("login remoto\n");
 

soc = open_sock_tcp(22);
if ( soc )
{

	ret = ssh_login(socket:soc, login:account, password:password);

	display("Exibindo ls via SSH \n");
	cmd000=ssh_cmd(socket:soc, cmd:"ls");	

	display(cmd000);	
	close(soc);	
	
	}

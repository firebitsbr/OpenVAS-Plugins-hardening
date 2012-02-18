# script_id 99439
# plugin_id BOOT-5139
# Wed 25 May 2011 01:02:13 PM BRT
# Mauro Risonho de Paula Assumpção
# Pentester/Analista em Segurança
# mauro.risonho@gmail.com

if(description)
{
script_id(99439);
script_copyright("Este script é Copyleft 2011 GNU 3");

script_version("1.0");
name["english"] = "BOOT-5139-Linux - Verificado por serviços na inicialização (chkconfig, runlevel 3 and 5)...";
desc["english"] = "Este script faz login na máquina remota e verifica por serviços na inicialização (chkconfig, runlevel 3 and 5)....
Risco: Baixo";
script_description(english:desc["english"]);
script_name(english:name["english"]);
family["english"] = "firebits-BOOT";

script_family(english:family["english"]);
summary["english"] = "Este script faz login na máquina remota e verifica por serviços na inicialização (chkconfig, runlevel 3 and 5)...";
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

#/etc/LILO

display("login remoto\n");
 

soc = open_sock_tcp(22);
if ( soc )
{

	ret = ssh_login(socket:soc, login:account, password:password);

	display("Verificado for Linux boot serviços (Red Hat style)\n");
	cmd000=ssh_cmd(socket:soc, cmd:"chkconfig --list | egrep '3:on|5:on' | awk '{ print $1 }'");	

	display(cmd000);	

	close(soc);	
	
	}

# script_id 99654
# plugin_id SNMP-3306
# Wed 25 May 2011 01:02:13 PM BRT
# Mauro Risonho de Paula Assumpção
# Pentester/Analista em Segurança
# mauro.risonho@gmail.com

if(description)
{
script_id(99654);
script_copyright("Este script é Copyleft 2011 GNU 3");

script_version("1.0");
name["english"] = "SNMP-3306-Linux - Verificar presença do daemon SNMP";
desc["english"] = "Este script faz login na máquina remota e verifica a presença do daemon SNMP.
Risk factor: Nenhum";
script_description(english:desc["english"]);
script_name(english:name["english"]);
family["english"] = "firebits-SSH-Security";

script_family(english:family["english"]);
summary["english"] = "Este script faz login na máquina remota e verifica a presença do daemon SNMP";
script_summary(english:summary["english"]);
script_dependencie("find_service2.nasl");
script_category(ACT_INIT);
exit(0);
}
 
include("misc_func.inc");
include("ssh_func.inc");
include("global_settings.inc");
 
account = "root";
password = "123456";

#account = "teste";
#password = "123";


#/etc/motd

display("login remoto\n");
 

soc = open_sock_tcp(22);
if ( soc )
{

	ret = ssh_login(socket:soc, login:account, password:password);

	display("daemon SNMP em execução\n");
	cmd000=ssh_cmd(socket:soc, cmd:"services snmpd status");	

	display(cmd000);	
	close(soc);	
	
	}

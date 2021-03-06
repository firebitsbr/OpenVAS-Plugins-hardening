# script_id 99167
# plugin_id SHLL-6240
# Wed 25 May 2011 01:02:13 PM BRT
# Mauro Risonho de Paula Assumpção
# Pentester/Analista em Segurança
# mauro.risonho@gmail.com

if(description)
{
script_id(99167);
script_copyright("Este script é Copyleft 2011 GNU 3");

script_version("1.0");
name["english"] = "SHLL-6240-Linux - which shells are available according /etc/shells";
desc["english"] = "Este script faz login na máquina remota e which shells are available according /etc/shells.
Risk factor: Nenhum";
script_description(english:desc["english"]);
script_name(english:name["english"]);
family["english"] = "firebits-SHLL-Security";

script_family(english:family["english"]);
summary["english"] = "Este script faz login na máquina remota e which shells are available according /etc/shells";
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

	display("which shells are available according /etc/shells\n");
	cmd000=ssh_cmd(socket:soc, cmd:"cat /etc/shells | grep "^/"");	

	display(cmd000);	
	close(soc);	
	
	}

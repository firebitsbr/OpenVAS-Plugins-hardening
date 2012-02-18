# plugin_id FILE-6312
# script_id 99435
# Wed 25 May 2011 01:02:13 PM BRT
# Mauro Risonho de Paula Assumpção
# Pentester/Analista em Segurança
# mauro.risonho@gmail.com

if(description)
{
script_id(99435);
script_copyright("Este script é Copyleft 2011 GNU 3");

script_version("1.0");
name["english"] = "FILE-6312-Linux - Verificado LVM volumes";
desc["english"] = "Este script faz login na máquina remota e verifica LVM volumes.
Risk Factor: Medium";
script_description(english:desc["english"]);
script_name(english:name["english"]);
family["english"] = "firebits-FILESYSTEM";

script_family(english:family["english"]);
summary["english"] = "Este script faz login na máquina remota e verifica LVM volumes";
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

	display("Exibindo o conteúdo do LVM volumes\n");
	cmd000=ssh_cmd(socket:soc, cmd:"vgdisplay | grep -v 'No volume groups found' | grep 'LV Name' | awk '{ print $3 }' | sort");	

	display(cmd000);	

	close(soc);	
	
	}

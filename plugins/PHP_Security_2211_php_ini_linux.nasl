# script_id 99977
# plugin_id PHP-2211
# Wed 25 May 2011 01:02:13 PM BRT
# Mauro Risonho de Paula Assumpção
# Pentester/Analista em Segurança
# mauro.risonho@gmail.com

if(description)
{
script_id(99977);
script_copyright("Este script é Copyleft 2011 GNU 3");

script_version("1.0");
name["english"] = "PHP-2211-Linux - Verificar php.ini presence";
desc["english"] = "Este script faz login na máquina remota e verifica a php.ini presence.
Risk factor: Nenhum";
script_description(english:desc["english"]);
script_name(english:name["english"]);
family["english"] = "firebits-PHP-Security";

script_family(english:family["english"]);
summary["english"] = "Este script faz login na máquina remota e verifica a php.ini presence";
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

#/etc/motd

display("login remoto\n");
 

soc = open_sock_tcp(22);
if ( soc )
{

	ret = ssh_login(socket:soc, login:account, password:password);

	display("Exibindo o conteúdo do php.ini\n");
	cmd000=ssh_cmd(socket:soc, cmd:"cat /etc/php.ini");	

	display("Exibindo a Localização do php.ini\n");
	cmd001=ssh_cmd(socket:soc , cmd:"ls /etc/php.ini");

	display("Exibindo evidência do php.ini\n");
	cmd002=ssh_cmd(socket:soc , cmd:"file /etc/php.ini");

	display(cmd000);	
	display(cmd001);
	display(cmd002);
	close(soc);	
	
	}

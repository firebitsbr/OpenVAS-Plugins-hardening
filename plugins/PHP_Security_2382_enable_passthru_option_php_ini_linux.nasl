# script_id 99966
# plugin_id PHP-2382
# Wed 25 May 2011 01:02:13 PM BRT
# Mauro Risonho de Paula Assumpção
# Pentester/Analista em Segurança
# mauro.risonho@gmail.com

if(description)
{
script_id(99966);
script_copyright("Este script é Copyleft 2011 GNU 3");

script_version("1.0");
name["english"] = "PHP-2382-Linux - Verificar presença de passthru option no php.ini";
desc["english"] = "Este script faz login na máquina remota e verifica a presença de passthru option no php.ini.
Risk factor: Nenhum";
script_description(english:desc["english"]);
script_name(english:name["english"]);
family["english"] = "firebits-PHP-Security";

script_family(english:family["english"]);
summary["english"] = "Este script faz login na máquina remota e verifica a presença de passthru option no php.ini";
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

	display("Exibindo o conteúdo do php.ini\n");
	cmd000=ssh_cmd(socket:soc, cmd:"cat /etc/php.ini | egrep -i 'passthru.*(off|no|0)' | grep -v '^;'");	

	display(cmd000);	
	close(soc);	
	
	}

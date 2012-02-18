# script_id 99649
# plugin_id SSHD-7414
# Wed 25 May 2011 01:02:13 PM BRT
# Mauro Risonho de Paula Assumpção
# Pentester/Analista em Segurança
# mauro.risonho@gmail.com

if(description)
{
script_id(99649);
script_copyright("Este script é Copyleft 2011 GNU 3");

script_version("1.0");
name["english"] = "SSHD-7414-Linux - Verificando opção do SSH: Protocol";
desc["english"] = "Este script faz login na máquina remota e Verificando opção do SSH: Protocol.
Risk factor: Nenhum";
script_description(english:desc["english"]);
script_name(english:name["english"]);
family["english"] = "firebits-SSH-Security";

script_family(english:family["english"]);
summary["english"] = "Este script faz login na máquina remota e Verificando opção do SSH: Protocol";
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

	display("Verificando opção do SSH: Protocol\n");
	cmd000=ssh_cmd(socket:soc, cmd:"cat /etc/ssh/sshd_config | grep "^Protocol" | awk '{ print $2 }'");	

	display(cmd000);	
	close(soc);	
	
	}

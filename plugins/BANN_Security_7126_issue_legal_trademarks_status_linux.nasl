# plugin_id BANN-7126
# script_id 99443
# Wed 25 May 2011 01:02:13 PM BRT
# Mauro Risonho de Paula Assumpção
# Pentester/Analista em Segurança
# mauro.risonho@gmail.com

if(description)
{
script_id(99443);
script_copyright("Este script é Copyleft 2011 GNU 3");

script_version("1.0");
name["english"] = "BANN-7126-Linux - Verificar issue file to see if it contains some form of message to discourage unauthorized users to leave the system alone";
desc["english"] = "Este script faz login na máquina remota e verifica por informações de auditorias disponíveis.
Risk Factor: Low";
script_description(english:desc["english"]);
script_name(english:name["english"]);
family["english"] = "firebits-hardening-BANNER";

script_family(english:family["english"]);
summary["english"] = "Este script faz login na máquina remota e verifica por informações de auditorias disponíveis";
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

	display("Exibindo o conteúdo do pacct\n");
	cmd000=ssh_cmd(socket:soc, cmd:"grep -i "linux" /etc/issue");	

	display(cmd000);	

	close(soc);	
	
	}

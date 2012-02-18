# plugin_id BANN-7124
# script_id 99980
# Wed 25 May 2011 01:02:13 PM BRT
# Mauro Risonho de Paula Assumpção
# Pentester/Analista em Segurança
# mauro.risonho@gmail.com

if(description)
{
script_id(99980);
script_copyright("Este script é Copyleft 2011 GNU 3");

script_version("1.0");
name["english"] = "BANN-7124-Linux - Verificar issue banner file";
desc["english"] = "Este script faz login na máquina remota e verifica a existência do arquivo issue banner.
Risk Factor: Low";
script_description(english:desc["english"]);
script_name(english:name["english"]);
family["english"] = "firebits-hardening-BANNER";

script_family(english:family["english"]);
summary["english"] = "Este script faz login na máquina remota e verifica a existência do arquivo issue banner.";
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

	display("Exibindo evidência do issue banner\n");
	cmd000=ssh_cmd(socket:soc, cmd:"file /etc/issue");	

	display("Exibindo o conteúdo do issue banner\n");
	cmd001=ssh_cmd(socket:soc, cmd:"cat /etc/issue");	

	display(cmd000);
	display(cmd001);	
	close(soc);	
	
	}

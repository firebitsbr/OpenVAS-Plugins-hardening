# plugin_id HTTP-6704
# script_id 99220
# Wed 25 May 2011 01:02:13 PM BRT
# Mauro Risonho de Paula Assumpção
# Pentester/Analista em Segurança
# mauro.risonho@gmail.com

if(description)
{
script_id(99220);
script_copyright("Este script é Copyleft 2011 GNU 3");

script_version("1.0");
name["english"] = "HTTP-6704-Linux - Verificar por Arquivo de Configuração do NGINX";
desc["english"] = "Este script faz login na máquina remota e verifica NGINX.
Risk Factor: Medium";
script_description(english:desc["english"]);
script_name(english:name["english"]);
family["english"] = "firebits-WEBSERVER";

script_family(english:family["english"]);
summary["english"] = "Este script faz login na máquina remota e verifica Arquivo de Configuração do NGINX";
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

	display("Exibindo o NGINX\n");
	cmd000=ssh_cmd(socket:soc, cmd:"ls /etc/nginx.conf");	

	display(cmd000);



	close(soc);	
	
	}

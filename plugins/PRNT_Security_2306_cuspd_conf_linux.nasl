# script_id 99922
# plugin_id PRNT-2306
# Wed 25 May 2011 01:02:13 PM BRT
# Mauro Risonho de Paula Assumpção
# Pentester/Analista em Segurança
# mauro.risonho@gmail.com

if(description)
{
script_id(99924);
script_copyright("Este script é Copyleft 2011 GNU 3");

script_version("1.0");
name["english"] = "PRNT-2306-Linux - Verificar evidência de arquivos de configuração do(s) Servidor(es) de Impressão";
desc["english"] = "Este script faz login na máquina remota, verificar evidência de arquivos de configuração do(s) Servidor(es) de Impressão.
Risk factor: Nenhum";
script_description(english:desc["english"]);
script_name(english:name["english"]);
family["english"] = "firebits-Print-Security";

script_family(english:family["english"]);
summary["english"] = "Este script faz login na máquina remota, verificar evidência de arquivos de configuração do(s) Servidor(es) de Impressão.";
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

	cmd000=ssh_cmd(socket:soc, cmd:"/etc/cups/cupsd.conf");	

	display("Exibindo evidência de arquivos de configuração do(s) Servidor(es) de Impressão\n");
	display(cmd000);
	close(soc);	
	
	}

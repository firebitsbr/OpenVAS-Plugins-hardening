# plugin_id FILE-6354
# script_id 99657
# Wed 25 May 2011 01:02:13 PM BRT
# Mauro Risonho de Paula Assumpção
# Pentester/Analista em Segurança
# mauro.risonho@gmail.com

if(description)
{
script_id(99657);
script_copyright("Este script é Copyleft 2011 GNU 3");

script_version("1.0");
name["english"] = "FILE-6354-Linux - Verificando se há arquivos com + de 3 meses em /tmp;
desc["english"] = "Este script faz login na máquina remota e verificar se há arquivos com + de 3 meses em /tmp.
Risk Factor: Medium";
script_description(english:desc["english"]);
script_name(english:name["english"]);
family["english"] = "firebits-FIREWALL";

script_family(english:family["english"]);
summary["english"] = "Este script faz login na máquina remota e verificando se há arquivos com + de 3 meses em /tmp;
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

	display("verificar se há arquivos com + de 3 meses em /tmp\n");
	cmd000=ssh_cmd(socket:soc, cmd:"find /tmp -type f -atime +3 | sed 's/ /!space!/g'");	

	display(cmd000);	
	close(soc);	
	
	}

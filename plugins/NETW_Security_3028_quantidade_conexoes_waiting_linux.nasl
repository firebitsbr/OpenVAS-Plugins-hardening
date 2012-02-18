# script_id 99875
# plugin_id NETW-3028
# Wed 25 May 2011 01:02:13 PM BRT
# Mauro Risonho de Paula Assumpção
# Pentester/Analista em Segurança
# mauro.risonho@gmail.com

if(description)
{
script_id(99875);
script_copyright("Este script é Copyleft 2011 GNU 3");

script_version("1.0");
name["english"] = "NETW-3028-Linux - Obter quantidade de conexões em 'waiting'";
desc["english"] = "Este script faz login na máquina remota, obtem quantidade de conexões em 'waiting'
Risk factor: Nenhum";
script_description(english:desc["english"]);
script_name(english:name["english"]);
family["english"] = "firebits-Firewall-Security";

script_family(english:family["english"]);
summary["english"] = "Este script faz login na máquina remota, obtem quantidade de conexões em 'waiting'";
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

	cmd000=ssh_cmd(socket:soc, cmd:"ifconfig -a | awk '{ if ($1=="inet") print $2 }' | cut -d ':' -f2");	

	display("Exibindo evidência de gateway(s) padrão.\n");
	display(cmd000);

	close(soc);	
	
	}

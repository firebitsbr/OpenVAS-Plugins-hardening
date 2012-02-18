# plugin_id MACF-6234
# script_id 99931
# Wed 25 May 2011 01:02:13 PM BRT
# Mauro Risonho de Paula Assumpção
# Pentester/Analista em Segurança
# mauro.risonho@gmail.com

if(description)
{
script_id(99931);
script_copyright("Este script é Copyleft 2011 GNU 3");

script_version("1.0");
name["english"] = "MACF-6234-Linux - Verificar mandatory access control (MAC) - AppArmor";
desc["english"] = "Este script faz login na máquina remota, exibe evidência(s) de mandatory access control (MAC) através SELinux e status.
Risk Factor: High";
script_description(english:desc["english"]);
script_name(english:name["english"]);
family["english"] = "firebits-M.A.C";

script_family(english:family["english"]);
summary["english"] = "Este script faz login na máquina e remota exibe evidência(s) de mandatory access control (MAC) através SELinux e status.";
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

	cmd000=ssh_cmd(socket:soc, cmd:"sestatus");	

	display("Exibindo evidência de mandatory access control (MAC) através SELinuxe status.\n");
	display(cmd000);

	close(soc);	
	
	}

# Legenda
# Se está setado no Grub
# sestatus

# Status SELinux
# sestatus 

# Serviços desprotegidos do SELinux
# ps -eZ | egrep "initrc" | egrep -vw "ps|tr|egrep|awk|bash" | tr ':' ' ' | awk '{ print $NF }'

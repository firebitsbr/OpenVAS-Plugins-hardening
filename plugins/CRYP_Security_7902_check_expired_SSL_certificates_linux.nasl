# plugin_id CRYP-7902
# script_id 99867
# Wed 25 May 2011 01:02:13 PM BRT
# Mauro Risonho de Paula Assumpção
# Pentester/Analista em Segurança
# mauro.risonho@gmail.com

if(description)
{
script_id(99867);
script_copyright("Este script é Copyleft 2011 GNU 3");

script_version("1.0");
name["english"] = "CRYP-7902-Linux - Verificar arquivos /etc/group e shadow group files no Linux";
desc["english"] = "Este script faz login na máquina remota e verificar arquivos /etc/group e shadow group files no Linux..
Risk Factor: Medium";
script_description(english:desc["english"]);
script_name(english:name["english"]);
family["english"] = "firebits-Encryption";

script_family(english:family["english"]);
summary["english"] = "Este script faz login na máquina remota e verificar arquivos /etc/group e shadow group files no Linux.";
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

	display("Verificar arquivos /etc/group e shadow group files no Linux\n");
	cmd000=ssh_cmd(socket:soc, cmd:"find / | grep "^ssl:certificates:" ${PROFILE} | cut -d ':' -f3");	

	display(cmd000);	

	close(soc);	
	
	}

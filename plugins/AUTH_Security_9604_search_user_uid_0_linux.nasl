# plugin_id AUTH-9204
# script_id 99917
# Wed 25 May 2011 01:02:13 PM BRT
# Mauro Risonho de Paula Assumpção
# Pentester/Analista em Segurança
# mauro.risonho@gmail.com

if(description)
{
script_id(99917);
script_copyright("Este script é Copyleft 2011 GNU 3");

script_version("1.0");
name["english"] = "AUTH-9204-Linux - Verificar por user com uid=0.";
desc["english"] = "Este script faz login na máquina remota e verificar por user com uid=0.
Risk Factor: High";
script_description(english:desc["english"]);
script_name(english:name["english"]);
family["english"] = "firebits-Authentication";

script_family(english:family["english"]);
summary["english"] = "Este script faz login na máquina remota e verificar por user com uid=0.";
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

	cmd000=ssh_cmd(socket:soc, cmd:"grep ':0:' /etc/passwd | egrep -v '^#|^root:|^:0:0:::' | cut -d ':' -f1,3 | grep ':0'");	

	display("Exibindo evidência(s) de user com uid=0.\n");
	display(cmd000);

	close(soc);	
	
	}


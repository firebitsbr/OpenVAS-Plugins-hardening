# script_id 99920
# plugin_id BOOT-5184
# Wed 25 May 2011 01:02:13 PM BRT
# Mauro Risonho de Paula Assumpção
# Pentester/Analista em Segurança
# mauro.risonho@gmail.com

if(description)
{
script_id(99920);
script_copyright("Este script é Copyleft 2011 GNU 3");

script_version("1.0");
name["english"] = "BOOT-5184-Linux - Verificar por ambiente de gravação em scripts startup";
desc["english"] = "Este script faz login na máquina remota e verificar por ambiente de gravação em scripts startup.
Risco: Médio";
script_description(english:desc["english"]);
script_name(english:name["english"]);
family["english"] = "firebits-BOOT";

script_family(english:family["english"]);
summary["english"] = "Este script faz login na máquina remota e verificar por ambiente de gravação em scripts startup.";
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

#/etc/issue.net

display("login remoto\n");
 

soc = open_sock_tcp(22);
if ( soc )
{

	ret = ssh_login(socket:soc, login:account, password:password);

	cmd000=ssh_cmd(socket:soc, cmd:"find /etc/init.d -type f -print");	
	cmd001=ssh_cmd(socket:soc, cmd:"find /etc/rc.d -type f -print");
	cmd002=ssh_cmd(socket:soc, cmd:"find /etc/rcS.d -type f -print");
	cmd003=ssh_cmd(socket:soc, cmd:"find /etc/rc0.d -type f -print");
	cmd004=ssh_cmd(socket:soc, cmd:"find /etc/rc1.d -type f -print");
	cmd005=ssh_cmd(socket:soc, cmd:"find /etc/rc2.d -type f -print");
	cmd006=ssh_cmd(socket:soc, cmd:"find /etc/rc3.d -type f -print");
	cmd007=ssh_cmd(socket:soc, cmd:"find /etc/rc4.d -type f -print");
	cmd008=ssh_cmd(socket:soc, cmd:"find /etc/rc5.d -type f -print");
	cmd009=ssh_cmd(socket:soc, cmd:"find /etc/rc6.d -type f -print");


	display("Exibindo evidência(s) no ambiente de gravação em scripts startup.\n");

	display(cmd000);
	display(cmd001);
	display(cmd002);
	display(cmd003);
	display(cmd004);
	display(cmd005);
	display(cmd006);
	display(cmd007);
	display(cmd008);
	display(cmd009);

	close(soc);	
	
	}

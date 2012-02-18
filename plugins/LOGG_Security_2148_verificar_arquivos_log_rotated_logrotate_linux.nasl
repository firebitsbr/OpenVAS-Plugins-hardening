# plugin_id LOGG-2148
# script_id 99202
# Wed 25 May 2011 01:02:13 PM BRT
# Mauro Risonho de Paula Assumpção
# Pentester/Analista em Segurança
# mauro.risonho@gmail.com

if(description)
{
script_id(99202);
script_copyright("Este script é Copyleft 2011 GNU 3");

script_version("1.0");
name["english"] = "LOGG-2148-Linux - Verificar se arquivos de log estão sendo “rotated” com logrotate";
desc["english"] = "Este script faz login na máquina remota e  Verificar se arquivos de log estão sendo “rotated” com logrotate
Risk Factor: High";
script_description(english:desc["english"]);
script_name(english:name["english"]);
family["english"] = "firebits-LOGGING";

script_family(english:family["english"]);
summary["english"] = "Este script faz login na máquina remota e  Verificar se arquivos de log estão sendo “rotated” com logrotate";
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

	display("Verificar se arquivos de log estão sendo “rotated” com logrotate\n");
	cmd000=ssh_cmd(socket:soc, cmd:"logrotate -d -v /etc/logrotate.conf 2>&1 | egrep "considering log|skipping" | grep -v '*' | sort | uniq | awk '{ if ($2=="log") { print $3 } }' | sed 's/\/*[a-zA-Z_.-]*$//g' | sort | uniq");	

	display(cmd000);

	close(soc);	
	
	}

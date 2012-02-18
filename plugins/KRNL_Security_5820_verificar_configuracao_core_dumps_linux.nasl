# plugin_id KRNL-5820
# script_id 99210
# Wed 25 May 2011 01:02:13 PM BRT
# Mauro Risonho de Paula Assumpção
# Pentester/Analista em Segurança
# mauro.risonho@gmail.com

if(description)
{
script_id(99210);
script_copyright("Este script é Copyleft 2011 GNU 3");

script_version("1.0");
name["english"] = "KRNL-5820-Linux - Verificar configuração core dumps (Linux)";
desc["english"] = "Este script faz login na máquina remota e Verificar configuração core dumps (Linux)
Risk Factor: Medium";
script_description(english:desc["english"]);
script_name(english:name["english"]);
family["english"] = "firebits-KERNEL";

script_family(english:family["english"]);
summary["english"] = "Este script faz login na máquina remota e Verificar configuração core dumps (Linux)";
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

	display("Verificar configuração core dumps - soft core (Linux)\n");
	cmd000=ssh_cmd(socket:soc, cmd:"cat /etc/security/limits.conf | awk '{ if ($1=="*" && $2=="soft" && $3=="core" && $4=="0") { print "soft core DESABILITADO" } else { print "soft core HABILITADO" } }'");	

	display("Verificar configuração core dumps - hard core (Linux)\n");
	cmd001=ssh_cmd(socket:soc, cmd:"cat /etc/security/limits.conf | awk '{ if ($1=="*" && $2=="hard" && $3=="core" && $4=="0") { print "hard core DESABILITADO" } else { print "hard core HABILITADO" } }'");	

	display(cmd000);
	display(cmd001);

	close(soc);	
	
	}

# plugin_id FILE-6374
# script_id 99857
# Wed 25 May 2011 01:02:13 PM BRT
# Mauro Risonho de Paula Assumpção
# Pentester/Analista em Segurança
# mauro.risonho@gmail.com

if(description)
{
script_id(99857);
script_copyright("Este script é Copyleft 2011 GNU 3");

script_version("1.0");
name["english"] = "FILE-6374-Linux - Verificar no root (/) se o filesystem suporta ACL - Linux.";
desc["english"] = "Este script faz login na máquina remota e verifica no root (/) se o filesystem suporta ACL - Linux.
Risk Factor: Medium";
script_description(english:desc["english"]);
script_name(english:name["english"]);
family["english"] = "firebits-FILESYSTEMS";

script_family(english:family["english"]);
summary["english"] = "Este script faz login na máquina remota e verifica no root (/) se o filesystem suporta ACL - Linux";
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

	display("Exibindo opções de montagem em /boot - Linux \n");
	cmd000=ssh_cmd(socket:soc, cmd:"/etc/fstab | awk '{ if ($2=='/boot') { print $4 } }");	

	display("Exibindo permissão no /etc/fstab - nodev - ACL - Linux \n");
	cmd001=ssh_cmd(socket:soc, cmd:"FIND / | awk '{ if ($1=='nodev') { print 'YES' } else { print 'NO' } }'");	

	display("Exibindo permissão no /etc/fstab - noexec - ACL - Linux \n");
	cmd002=ssh_cmd(socket:soc, cmd:"FIND / | awk '{ if ($1=='noexec') { print 'YES' } else { print 'NO' } }'");	

	display("Exibindo permissão no /etc/fstab - nosuid - ACL - Linux \n");
	cmd003=ssh_cmd(socket:soc, cmd:"FIND / | awk '{ if ($1=='nosuid') { print 'YES' } else { print 'NO' } }'");	

	display(cmd000);	
	display(cmd001);	
	display(cmd002);	
	display(cmd003);	

	close(soc);	
	
	}

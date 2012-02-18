# plugin_id FILE-6323
# script_id 99798
# Wed 25 May 2011 01:02:13 PM BRT
# Mauro Risonho de Paula Assumpção
# Pentester/Analista em Segurança
# mauro.risonho@gmail.com

if(description)
{
script_id(99798);
script_copyright("Este script é Copyleft 2011 GNU 3");

script_version("1.0");
name["english"] = "FILE-6323-Linux - Verificar o tipo de filesystem (ext2, ext3 ou ext4) - Linux";
desc["english"] = "Este script faz login na máquina remota e verifica o tipo de filesystem (ext2, ext3 ou ext4) - Linux.
Risk Factor: Medium";
script_description(english:desc["english"]);
script_name(english:name["english"]);
family["english"] = "firebits-FILESYSTEM";

script_family(english:family["english"]);
summary["english"] = "Este script faz login na máquina remota e verifica o tipo de filesystem (ext2, ext3 ou ext4) - Linux";
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

	display("Exibindo o filesystem);
	cmd000=ssh_cmd(socket:soc, cmd:"mount -t ext2,ext3,ext4 | awk '{ print $3','$5 }'");	


	display(cmd000);	

	close(soc);	
	
	}


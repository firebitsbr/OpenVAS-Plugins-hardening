# script_id 99440
# plugin_id BOOT-5121
# Wed 25 May 2011 01:02:13 PM BRT
# Mauro Risonho de Paula Assumpção
# Pentester/Analista em Segurança
# mauro.risonho@gmail.com


if(description)
{
script_id(99440);
script_copyright("Este script é Copyleft 2011 GNU 3");

script_version("1.0");
name["english"] = "BOOT-5121-Linux - Verificado por GRUB boot loader";
desc["english"] = "Este script faz login na máquina remota e verifica por GRUB boot loader.
Risco: Baixo";
script_description(english:desc["english"]);
script_name(english:name["english"]);
family["english"] = "firebits-BOOT";

script_family(english:family["english"]);
summary["english"] = "Este script faz login na máquina remota e verifica por GRUB boot loader";
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

#/etc/GRUB

display("login remoto\n");
 

soc = open_sock_tcp(22);
if ( soc )
{

	ret = ssh_login(socket:soc, login:account, password:password);

	display("Exibindo o conteúdo do GRUB e verificando se o password está em MD5\n");
	cmd000=ssh_cmd(socket:soc, cmd:"cat /boot/grub/grub.cfg | grep 'password --md5' | grep -v '^#'");	
	cmd001=ssh_cmd(socket:soc, cmd:"cat /boot/grub/grub.conf | grep 'password --md5' | grep -v '^#'");

	display(cmd000);	
	display(cmd001);	

	close(soc);	
	
	}

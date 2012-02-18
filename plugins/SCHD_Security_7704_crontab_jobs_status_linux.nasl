# script_id 99901
# plugin_id SCHD-7704
# Wed 25 May 2011 01:02:13 PM BRT
# Mauro Risonho de Paula Assumpção
# Pentester/Analista em Segurança
# mauro.risonho@gmail.com

if(description)
{
script_id(99901);
script_copyright("Este script é Copyleft 2011 GNU 3");

script_version("1.0");
name["english"] = "SCHD-7704-Linux - Verificar o status do Crontab e o Jobs";
desc["english"] = "Este script faz login na máquina remota e verifica o status do Crontab e o Jobs.
Risk factor: Nenhum";
script_description(english:desc["english"]);
script_name(english:name["english"]);
family["english"] = "firebits-Schedule-Security";

script_family(english:family["english"]);
summary["english"] = "Este script faz login na máquina remota e verifica o status do Crontab e o Jobs";
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

#/etc/motd

display("login remoto\n");
 

soc = open_sock_tcp(22);
if ( soc )
{

	ret = ssh_login(socket:soc, login:account, password:password);

	cmd000=ssh_cmd(socket:soc, cmd:"crontab -l");
	cmd001=ssh_cmd(socket:soc, cmd:"/etc/cron.hourly");	
	cmd002=ssh_cmd(socket:soc, cmd:"/etc/cron.daily");	
	cmd003=ssh_cmd(socket:soc, cmd:"/etc/cron.weekly");	
	cmd004=ssh_cmd(socket:soc, cmd:"/etc/cron.monthly");	


	display(cmd000);	
	display(cmd001);
	display(cmd002);
	display(cmd003);
	display(cmd004);


	close(soc);	
	
	}

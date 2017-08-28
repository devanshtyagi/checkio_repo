#!/lfs/arch/admin/perl/perl-5.10.0/bin/perl
use lib "/home/qxf8083/perl5/lib/perl5";
use warnings;
use Net::OpenSSH;
use POSIX qw(strftime);

$host=shift;

sub remote_ssh
{
        my $server = shift;
        chomp($server);
        my $ssh = Net::OpenSSH->new($server,master_opts => ['-F' => '/www/mwadm/etc/.ssh/samconf']);
        $ssh->error and die "SSH connection failed: " . $ssh->error;
        return $ssh;
        print $ssh->error();
}

sub read_process_stack
{
	my $pid=shift;
	my $ssh=&remote_ssh($host);
	my $getProcessStack="sudo cat /proc/$pid/stack";
	my ($ProcessStack,$error)=$ssh->capture2($getProcessStack);
	print "Stack trace:\n";
	print $ProcessStack,"\n";
	print $error,"\n";
	my $getProcessWchan="sudo cat /proc/$pid/wchan";
	my ($ProcessWchan,$error1)=$ssh->capture2($getProcessWchan);
	return $ProcessWchan;
}

sub check_process_heartbeat
{
	my $pid=shift;
	my $alive="yes";
	my $dead="no";
	my $get_total_intr="sudo cat /proc/$pid/schedstat|awk '{print\$3}'";
	my $ssh=&remote_ssh($host);
	for(my $i=0;$i<5;$i++)
	{
		my ($total_intr,$error)=$ssh->capture2($get_total_intr);
		push (@heartbeat,$total_intr);
		sleep 1;
	}
	if ($heartbeat[0]==$heartbeat[1] && $heartbeat[1]==$heartbeat[2] && $heartbeat[2]==$heartbeat[3] && $heartbeat[3]==$heartbeat[4])
	{
		return $dead;
	}
	else
	{
		return $alive;
	}
}


sub profiler
{
	my $pid=shift;
	my $ssh=&remote_ssh($host);
	my $getProcessStack="sudo cat /proc/$pid/stack";
	my ($ProcessStack,$error)=$ssh->capture2($getProcessStack);
	`>syscallfile.txt`;
	my $getProcessSyscall="sudo cat /proc/$pid/syscall|awk '{print\$1}'";
	print "A poor man's profiling in progress";
	for(my $i=0;$i<100;$i++)
	{
		print ".";
		my ($Syscall,$error1)=$ssh->capture2($getProcessSyscall);
		open my $handle, ">>", "syscallfile.txt" or die("Could not open file. $!");
        	print $handle $Syscall;
        	close $handle;	
		sleep 1;
	}
	my $profop=`cat syscallfile.txt|sort | uniq -c |sort -nr|tr -s ' ' ' '|tr -s '\n' ' '`;
	my @arr=split(' ',$profop);
	print "\n%      -     System call\n";
	for (my $i=0;$i<($#arr+1)/2;$i++)
	{
	my $getSyscallname="sudo grep -w $arr[$i+1] /usr/include/asm/unistd_64.h|awk '{print\$2}'";
	my ($syscallname,$error2)=$ssh->capture2($getSyscallname);
		if($syscallname)
		{
			print $arr[$i],"    -     ",$syscallname,"\n";
		}
		else
		{
			print $arr[$i],"    -     ",$arr[$i+1],"\n";
		}
	}
	`>syscallfile.txt`;	
		
}

sub check_nfs
{
	my $pid=shift;
	my $ssh=&remote_ssh($host);
	my $getopenNFS="sudo lsof -N |grep -w  $i|awk '{print\$10}'|sort | uniq |cut -d '(' -f2 | cut -d ')' -f1";
	my ($openNFS,$error)=$ssh->capture2($getopenNFS);
	print $error,"\n";
	my @nfsList=split('\n',$openNFS);
	foreach $i (@nfsList)
	{
		my $getmountpoint="sudo mount | grep $i | awk '{print\$3}'";
		my ($mountpoint,$error1)=$ssh->capture2($getmountpoint);
		chomp ($mountpoint);
		push(@mountList,$mountpoint);
	}
	foreach $j (@mountList)
	{
		my $getNFSstats="sudo /usr/sbin/nfsiostat 1 5 $j";
		my ($NFSstats,$error2)=$ssh->capture2($getNFSstats);
		print "NFS stats for the mount $j are:\n";
		print $NFSstats,"\n";
		print $error2,"\n";
	}
	
}
#####################main#########################
my $ssh=&remote_ssh($host);
my $getDprocs_list="ps -eo pid,ppid,pcpu,cputime,stat,wchan:14,comm| awk '\$5!~/S/'|grep -vw ps";
my ($Dprocs_list,$error1)=$ssh->capture2($getDprocs_list);

print "\nList of processes which are not in Sleep state:\n";
print " PID  PPID  CPU% CPUTIME STATUS WCHAN        COMMAND\n";
print $Dprocs_list,"\n";

print "\nEnter comma-separated list of processes (PIDs) you want to analyze:";
my $Dprocs_pids=<STDIN>;
chomp ($Dprocs_pids);
my @Dpids=split (',',$Dprocs_pids);


foreach $i (@Dpids)
{
	print "---$i---";
	print "--------\n";
	my $wchan=&read_process_stack($i);
	my $check_heartbeat=&check_process_heartbeat($i);
		if($check_heartbeat eq "no")
		{
			print "Process $i has no heartbeat (in the last 5 sec)\n";
		}		
		else
		{
			print "Process $i is still alive\n";
		}
	print "\nDo you want to profile this process for 100 seconds(y/n)?:";
        my $ans=<STDIN>;
	chomp($ans);
        	if($ans eq "y")
        	{
                        &profiler($i);
                }
                else
                {
                        print "Skipping profiler\n";
                }
	if ($wchan=~ m/nfs/ || $wchan=~m/rpc/)
	{
		&check_nfs($i);
	}
	else
	{
		print "\nDo you want to check stats of the NFS shares related to this process(y/n)?:";
		my $a=<STDIN>;
		chomp ($a);
		if ($a eq "y")
		{
			&check_nfs($i);
		}
		else
		{
			print "Skipping nfs checks...\n";

		}
	}
	
}	


rule k3e9_1395b6ab4e400916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.1395b6ab4e400916"
     cluster="k3e9.1395b6ab4e400916"
     cluster_size="5887"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ipamor backdoor syzbaukwkdpb"
     md5_hashes="['000e7d4785e79fef239601ba634e8dc5','0023c6c05b5adfd824d0f876f98ccb37','00cc504a051c975173b47a4848ef881d']"

   strings:
      $hex_string = { 8d65f45b5e5f5dc389fb31f68d742600e89b09ffff2b45e81b55ec39f27206771e39d8731a89f929c1528b4508525150e8ab90faff83c41083f8d974d3ebc1b8 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}

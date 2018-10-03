
rule n2319_13995adb2a210912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.13995adb2a210912"
     cluster="n2319.13995adb2a210912"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="miner coinminer cryxos"
     md5_hashes="['9661813c949e0cfd3033ee63176f6494b8891f22','4aa9db240bc874b069f6f1def289ccacd2fd3918','8e97119e9e66ff7135030e89e3096b53d4d003ef']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.13995adb2a210912"

   strings:
      $hex_string = { 5d2c2131292e6c656e6774687d7d293b76617220792c7a3d612e646f63756d656e742c413d2f5e283f3a5c732a283c5b5c775c575d2b3e295b5e3e5d2a7c2328 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}


rule k3e9_0b92dcc9cc000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.0b92dcc9cc000912"
     cluster="k3e9.0b92dcc9cc000912"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="rincux ddos stormattack"
     md5_hashes="['08c6b8093560b4f72b8d510bac046ee3','3e0051a98d6553f665894cd279765164','8089cd798893cb8fc18fe58ae8df2126']"

   strings:
      $hex_string = { 6b1f9542b5d9e2de60b6eed1d31ad19bb97b0c2c93cd84516d36a13422b11c859140e4efa2532473dc9faa41b6c82014cb7c04da0303797a67ae38d6560ab24f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}

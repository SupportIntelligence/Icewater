
rule n2319_139917a1c2000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.139917a1c2000b32"
     cluster="n2319.139917a1c2000b32"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="likejack faceliker clicker"
     md5_hashes="['43b0c858f3f64524bac5aad079ae9a458f7adeaa','1560078ca19fb21872974b05d9280b43e381b8b6','84e6d581102ce399744ae57bcb16fd2dfc0173ae']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.139917a1c2000b32"

   strings:
      $hex_string = { 5d2a295c732a5c5d2f672c223d272431275d22293b696628216b2e6973584d4c286129297472797b696628657c7c216c2e6d617463682e50534555444f2e7465 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}

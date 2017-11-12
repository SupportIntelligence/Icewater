
rule m3e9_4e5e2d4bc6620b22
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.4e5e2d4bc6620b22"
     cluster="m3e9.4e5e2d4bc6620b22"
     cluster_size="3463"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="kazy cfca heuristic"
     md5_hashes="['0048e2d4d7ff354b491c886fd7d524cc','005576afaf06d49289756ab3ce7acce6','01e96f376dc1317b331061773912618f']"

   strings:
      $hex_string = { 800fe834d19512ac49f97370ca380e0b7632a1bfe720216a195ef74bf6c0ed80c261158814011505034308a35e1d0a0c4109b28c13e9ecd3782b074f8a470129 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}

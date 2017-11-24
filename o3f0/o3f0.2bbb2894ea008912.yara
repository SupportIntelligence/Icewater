
rule o3f0_2bbb2894ea008912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3f0.2bbb2894ea008912"
     cluster="o3f0.2bbb2894ea008912"
     cluster_size="282"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="malicious conficker engine"
     md5_hashes="['01075bd65d14e171ab544e8563cfb856','017ab4b6c48d6d498c9688085504a2dc','109f40a604d9d94e73c239be053518f1']"

   strings:
      $hex_string = { f439f839fc39003a0000083a0c3a103a143a183a0000203a243a200a200a00000000300a3c3a403a443a00004c3a0000543a583a5c3a600a643a683a600a700a }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}

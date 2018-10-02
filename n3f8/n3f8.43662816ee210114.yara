
rule n3f8_43662816ee210114
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f8.43662816ee210114"
     cluster="n3f8.43662816ee210114"
     cluster_size="256"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="banker androidos origin"
     md5_hashes="['71f743ef17cd5a736facefc964882ea5b088b518','968f4edd4e9af42189c5b881777504e996671340','599c42b1c51cdc0f0523f8d95d4269fe8162a1b9']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n3f8.43662816ee210114"

   strings:
      $hex_string = { 08025460c0037220500f700070516409763228d65362c2039c02080270405f0926135a64c20328e75461c1037110390e00000c0072304f0f710028dd6e103006 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}

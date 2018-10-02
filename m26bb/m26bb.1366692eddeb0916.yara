
rule m26bb_1366692eddeb0916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.1366692eddeb0916"
     cluster="m26bb.1366692eddeb0916"
     cluster_size="194"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="brothersoft malicious dealply"
     md5_hashes="['fe153386fca0c5e1c55674c44abbdaed5df4bbb3','21569516ebfdb52b76f642547b9554bb1f24043d','0321168ab3babe4a1b3db376d9a0ae146a50f7b6']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.1366692eddeb0916"

   strings:
      $hex_string = { 8c059229bda98eec5a75e487284bc4bad4eaa524c798b25d4c47b046de7dc603b499fc49f53756e923bcd6c8a164e0af6c4ead9a675ee27bcbf86d97ace839e7 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}


rule k3e9_0935a42dda52f936
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.0935a42dda52f936"
     cluster="k3e9.0935a42dda52f936"
     cluster_size="10"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="nimnul vjadtre wapomi"
     md5_hashes="['18493551884f02e5dbb55bab8c9fa32c','1f816618d4cc84643fc339a0f54d1cc6','de8de7eaf60f6d2f99e6fe37aedc22a4']"

   strings:
      $hex_string = { d8e06cb511e73ba67e5a968fcf2e68ce95dc203776fa3605876d8e44a4f3545f1821e8f835eee6f0341e9b83e97cd63e6ff4b716a559acf12055807bd1780117 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}

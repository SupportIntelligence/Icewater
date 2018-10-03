
rule j26df_29996848c0000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j26df.29996848c0000932"
     cluster="j26df.29996848c0000932"
     cluster_size="384"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="mawanella scriptworm email"
     md5_hashes="['68b317666cfd16c744537d8af6dab993e3517c21','575e469c66b2405f6da52d10c1e76093c62fc98e','d1807b2c2a89e2292f8f02e045c928f5071baf36']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j26df.29996848c0000932"

   strings:
      $hex_string = { f4f85b202e19f7bfcf31f6832883b57f0830432042f4b27f701bb43bbadb01cd217252b43c33c9baed01cd2193b440b90a06ba2001cd21e83720b8023dbae401 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}

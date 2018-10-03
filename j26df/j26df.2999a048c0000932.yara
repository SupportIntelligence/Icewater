
rule j26df_2999a048c0000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j26df.2999a048c0000932"
     cluster="j26df.2999a048c0000932"
     cluster_size="2769"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="mawanella scriptworm loveletter"
     md5_hashes="['87428931f5854f5f2b786e282cbf246c900e1c42','058060b0b535f51b004dfc3b4db42419550229c2','487110bd30967961b84b1b7d41f2b089ef33ed5f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j26df.2999a048c0000932"

   strings:
      $hex_string = { f4f85b202e19f7bfcf31f6832883b57f0830432042f4b27f701bb43bbadb01cd217252b43c33c9baed01cd2193b440b90a06ba2001cd21e83720b8023dbae401 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}

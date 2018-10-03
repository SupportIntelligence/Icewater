
rule nfc8_299293b9caa00b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=nfc8.299293b9caa00b12"
     cluster="nfc8.299293b9caa00b12"
     cluster_size="17"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos banker asacub"
     md5_hashes="['02b005fdcf00a60b2831780efac399435b1d1f9d','684ae6d25974c4fe4478cc36d45cec90d595ac1a','144a76abb3cca09f42887fc189ef78df24eb46b4']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=nfc8.299293b9caa00b12"

   strings:
      $hex_string = { 7d4ba0ba7f40e723e88b5692948f58503a5d801c862bf31304fdbbc4460597640f257c29aaa9067288ccaff4b8f220a70a6dd1deeed948985e34c83119a8275f }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}

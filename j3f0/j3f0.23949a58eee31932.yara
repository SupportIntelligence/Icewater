
rule j3f0_23949a58eee31932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f0.23949a58eee31932"
     cluster="j3f0.23949a58eee31932"
     cluster_size="5"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="graftor malicious patched"
     md5_hashes="['077cb141991f80ef7bff36aa06d6ebad','4ff2690da1820c5dd21c3b8b8901560d','c847b7e7d7983ae629fcfacad67aa566']"

   strings:
      $hex_string = { 721d8b3989382bf203c203ca3bf273f285f674148a11881040414e75f7eb098a11881040414e75f70fb6314183fe1073570fb611c1ea02c1e6068db432010700 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}

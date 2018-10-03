
rule k2319_39153569c8800932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.39153569c8800932"
     cluster="k2319.39153569c8800932"
     cluster_size="7"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['1056f0270ea097366eb3f6001d80d67c2c641870','8d3712bf56e67c2f86155d48f35cb7ac1d92bd45','62b9e0c4acc88b95ab856d58570eaffc8ba1491e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.39153569c8800932"

   strings:
      $hex_string = { 627265616b7d3b666f7228766172206d304a20696e20593657304a297b6966286d304a2e6c656e6774683d3d3d282830783146432c312e3438394533293c3078 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}

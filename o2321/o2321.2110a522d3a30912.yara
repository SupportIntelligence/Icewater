
rule o2321_2110a522d3a30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o2321.2110a522d3a30912"
     cluster="o2321.2110a522d3a30912"
     cluster_size="152"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="graftor hacktool noobyprotect"
     md5_hashes="['0245a9f521ec7d50c88f01fd73ec1341','07a672791691d41ed12a6e928870fe12','1d0329a6f792faa98ab2763be221b3c3']"

   strings:
      $hex_string = { a98d7c864b92a3bbad3f8a3e0f64a89fac18e4497daff7fc6cdd42ebe66a67985e2b53669cfb2a726bbd209bd0379d94b287cf717fc728e3f425a5f61ab3b4c1 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}

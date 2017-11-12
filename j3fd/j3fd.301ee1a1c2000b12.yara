
rule j3fd_301ee1a1c2000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3fd.301ee1a1c2000b12"
     cluster="j3fd.301ee1a1c2000b12"
     cluster_size="28"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="toolbar webtoolbar downtango"
     md5_hashes="['025e3079e61e58d527a729dda34f9c75','0cd874e5d7b8720dfbab631cfcf0984c','8a5f1ddb4533f69f145f737fb64b567d']"

   strings:
      $hex_string = { 5c5fda3ef30f0a093522dbdbc03f00f9e60d5d67d1fda01e032bd940f7becc87665480a6a3b8f51962d5d226b19826ee9acb44a7455a8195151af55130820493 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}

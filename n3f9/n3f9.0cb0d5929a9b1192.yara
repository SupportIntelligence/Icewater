
rule n3f9_0cb0d5929a9b1192
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f9.0cb0d5929a9b1192"
     cluster="n3f9.0cb0d5929a9b1192"
     cluster_size="55"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="lyposit zusy ransom"
     md5_hashes="['051b597cfc31fc0ce688a03fd3af8090','146ddaa6f5f9add7e627ab66c2a896bb','b06cd6e67455e62f1b3da567b6232380']"

   strings:
      $hex_string = { 65f56bbaf35210f02a85f80429ca614ee2aae988cb6a1258ef11b83cda3ef7a6b1bffd7b30fff9b9927d7371fc20873d74453b1f535b28c6b49e691c050e259a }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}

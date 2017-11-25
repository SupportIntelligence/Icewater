
rule n3f1_491e9499c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f1.491e9499c2200b12"
     cluster="n3f1.491e9499c2200b12"
     cluster_size="220"
     filetype = "application/zip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="obfus androidos andr"
     md5_hashes="['003e1dea1f424c3ea3b0d953e931d085','00b6d157255ad9d170e64ea47fb2579c','167dd997f25a40bb84a15a6b2dca7749']"

   strings:
      $hex_string = { 07803b0db5c6d0986d168a29f57d9a05096e5aadaa6a9b82340c657d7fbfd96c589c99558b59d72ef6e63fdaf81637cdbb8dce17e8fa568e1ec06f4c25f2141b }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}

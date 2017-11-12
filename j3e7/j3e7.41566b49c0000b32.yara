
rule j3e7_41566b49c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3e7.41566b49c0000b32"
     cluster="j3e7.41566b49c0000b32"
     cluster_size="9"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="malicious corrupt corruptfile"
     md5_hashes="['0e53c6e2cb52d3c2119b795a827ed1bd','208337286dfe8a92cd8d2d6affb65efb','c5b72aa65bd6d37789d13e07b0c26680']"

   strings:
      $hex_string = { 338d4c240c8d5424048bc5e85dfbffff837c240c0075b18d4c240c8b5424088b442404e825fdffff8b042433d28910e9900000008d4c24048bd78bc6e894fcff }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}

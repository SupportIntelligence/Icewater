
rule j3f8_7094d6c348000330
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f8.7094d6c348000330"
     cluster="j3f8.7094d6c348000330"
     cluster_size="38"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shedun androidos piom"
     md5_hashes="['058122f4d3af03671f996143409e1bd4','0cb8e091c7747152065fde90d95bbf14','7e2c18ad2aa63cef4e68db2b62c79f66']"

   strings:
      $hex_string = { 086d436f6e7465787400136d496e697469616c4170706c69636174696f6e000e6d4c6f63616c50726f766964657200096d5061636b61676573000c6d50726f76 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}

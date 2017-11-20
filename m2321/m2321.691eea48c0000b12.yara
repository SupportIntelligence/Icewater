
rule m2321_691eea48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.691eea48c0000b12"
     cluster="m2321.691eea48c0000b12"
     cluster_size="10"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['01648c6a6c7edac318aa7bbfadbc0d87','0fd540d5c09115ccfa26f85d8ed20c60','ba20ed949e30a0f27a0fdaefbade6b09']"

   strings:
      $hex_string = { 00d6b13e357baa2b889547a80651db6b4ee578660b54f9e63408e987fba07c696476521738ccfe0df29ed2ca556ee861eeb3294df69ae6532ee4c1a75ef55925 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}

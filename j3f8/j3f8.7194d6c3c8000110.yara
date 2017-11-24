
rule j3f8_7194d6c3c8000110
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f8.7194d6c3c8000110"
     cluster="j3f8.7194d6c3c8000110"
     cluster_size="393"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shedun androidos piom"
     md5_hashes="['0068b7e607c330926b1a46ffbbeb5dba','00f9df36baa8cbc7afeccfaa452f1a39','06c64ad20c3e34a84274ffc69ffcf7fa']"

   strings:
      $hex_string = { 63742f4669656c643b001a4c6a6176612f6c616e672f7265666c6563742f4d6574686f643b00154c6a6176612f7574696c2f41727261794c6973743b00164c6a }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}

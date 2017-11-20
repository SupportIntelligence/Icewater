
rule k2321_3310d846d7a31932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.3310d846d7a31932"
     cluster="k2321.3310d846d7a31932"
     cluster_size="5"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="hupigon backdoor razy"
     md5_hashes="['0819c19097dbf71943cdb6c1d92db80f','1bf3ee02a189a7c59dccc1782297741d','fb3c5d9ac1be6f16fcf0e65040f6d7e8']"

   strings:
      $hex_string = { 27ddc56563ac231c2b0ff35046fa10ca3f585c7b20b987b54ee3d68913b1a315c334d94bc67ca2eaed3ae85ebc560d248d6fb6f209b4f46d49f13b724fd59cee }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}

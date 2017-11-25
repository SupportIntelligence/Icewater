
rule j3f4_23b46a08c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f4.23b46a08c0000b32"
     cluster="j3f4.23b46a08c0000b32"
     cluster_size="5"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="razy malicious engine"
     md5_hashes="['21a9504c0523efbc24c41df24c7058dd','367505bdf96473c237110884cb1cd9a7','f6c982a50610f53fa2c2c062462702a1']"

   strings:
      $hex_string = { 312e302e302e3022206e616d653d224d794170706c69636174696f6e2e617070222f3e0d0a20203c7472757374496e666f20786d6c6e733d2275726e3a736368 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}

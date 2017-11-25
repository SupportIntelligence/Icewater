
rule m3e9_751c97c9c4000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.751c97c9c4000b32"
     cluster="m3e9.751c97c9c4000b32"
     cluster_size="2426"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['0012eec8017b9e27da950105117f05c1','0067bc8c8f4894d4164eb9f11aeaebd7','021d9346b97ec38b46fb31597e2d4fe0']"

   strings:
      $hex_string = { 760b880e464f408a0884c975e185ff7403c606005f5e8a0880f920740580f909750340ebf15dc20c00cccccccccc8bff558bec83ec44a13c200101578b7d086a }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}

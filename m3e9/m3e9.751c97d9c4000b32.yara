
rule m3e9_751c97d9c4000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.751c97d9c4000b32"
     cluster="m3e9.751c97d9c4000b32"
     cluster_size="14564"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['0003cd2c677c72fa3f395b12af365ac1','001bdf4108b698781fbfac12d2445b1e','00e0405dae85d90cd8184be072deae43']"

   strings:
      $hex_string = { 760b880e464f408a0884c975e185ff7403c606005f5e8a0880f920740580f909750340ebf15dc20c00cccccccccc8bff558bec83ec44a13c200101578b7d086a }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}

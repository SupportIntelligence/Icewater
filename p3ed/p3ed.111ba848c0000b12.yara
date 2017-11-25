
rule p3ed_111ba848c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=p3ed.111ba848c0000b12"
     cluster="p3ed.111ba848c0000b12"
     cluster_size="247"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="zusy ransom exploit"
     md5_hashes="['01028c9218d951c650168eed38b3e3d7','01763c071e2575c34d2803874206bd15','0a6f73fba0b669113ebec643dcf84970']"

   strings:
      $hex_string = { 6ade388efc6226f40a643e3fdb6b0170be0ebabbb9689034c31a6fb4094154ac61ad7ae9a75c86e718f1cad095b3c0b6800f0c69eef50727469b77fbcf81d39d }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}

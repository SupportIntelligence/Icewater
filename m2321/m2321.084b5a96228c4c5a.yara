
rule m2321_084b5a96228c4c5a
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.084b5a96228c4c5a"
     cluster="m2321.084b5a96228c4c5a"
     cluster_size="5"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jadtre otwycal wapomi"
     md5_hashes="['2597ec97caecec995cf29a68928310dc','32a5c0513e1277cd4a2eb84a83f2c2b9','d1e795154ccc05480470f0c58a631632']"

   strings:
      $hex_string = { 6d721fe54d7e12db63f003e3ce9a6a26c4a4410aeebfc0f4d933c695b851914559a5adf21955bb4e1b0c3d05cdd09e6c32fa69d479ac2c075be2977ce858315e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}

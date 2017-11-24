
rule k2321_293a4d4bdaabd932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.293a4d4bdaabd932"
     cluster="k2321.293a4d4bdaabd932"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ccpk mira icgh"
     md5_hashes="['18e6d585bc78c0ec724337f4e10983d0','c18a55f4043195bf26ae44c5c35b2afa','f2a4a2833dc6a15bbdc50758099d7001']"

   strings:
      $hex_string = { 3b4d5a9e217c0fd6cb3266ab5ca5d82a7dd1e4c54b8ae89033a759d9cf024e8520f10a9835b701ccc6d57160f6aa16cc1aa89d40e00c898cc019884306b36da4 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}

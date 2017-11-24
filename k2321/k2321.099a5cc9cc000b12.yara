
rule k2321_099a5cc9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.099a5cc9cc000b12"
     cluster="k2321.099a5cc9cc000b12"
     cluster_size="22"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="rincux ddos stormattack"
     md5_hashes="['0262c356e63bd93d7d2da3215a43171b','098d5c0533b0390d7d7e2f3f52767eff','ca23070ff8499ccc2a32b0ad44f9a735']"

   strings:
      $hex_string = { 800e501a8fbe85ab3c6d7059da5ec188010cb7b5b0e3e23b2d039ef6ec0b92d4f2756f0ce2361fba23f170d790ca221e3edb261debb800e47b4e7cfffc9f9781 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}

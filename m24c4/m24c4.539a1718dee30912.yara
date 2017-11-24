
rule m24c4_539a1718dee30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m24c4.539a1718dee30912"
     cluster="m24c4.539a1718dee30912"
     cluster_size="4"
     filetype = "MS-DOS executable (gzip compressed data"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="enistery pemalform riskware"
     md5_hashes="['365298940ce53cd31ce3162a260deaa9','7a7ecfc045b132d4ce117d413fa4b187','ee3567734174562d30d6799cceea7e1d']"

   strings:
      $hex_string = { 55ee3f34999206a5e16ede1621d313e75dd77c7db6e363c9f8401bc589537966d6e4447a5ca2fcfecb9a5fdcd597e92d9d8ac46b1add154dd2cfaed4bc8fdb77 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}

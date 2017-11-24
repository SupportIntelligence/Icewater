
rule m2321_539a1718dee30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.539a1718dee30912"
     cluster="m2321.539a1718dee30912"
     cluster_size="5"
     filetype = "MS-DOS executable (gzip compressed data"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="enistery dynamer pemalform"
     md5_hashes="['365298940ce53cd31ce3162a260deaa9','72270074b525ad3ed03b16f71560ddb0','cf70cbd04416ca75989a29c73028b49b']"

   strings:
      $hex_string = { 55ee3f34999206a5e16ede1621d313e75dd77c7db6e363c9f8401bc589537966d6e4447a5ca2fcfecb9a5fdcd597e92d9d8ac46b1add154dd2cfaed4bc8fdb77 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}

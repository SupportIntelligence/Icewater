
rule m2321_0b3488aa33656b36
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.0b3488aa33656b36"
     cluster="m2321.0b3488aa33656b36"
     cluster_size="9"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="midie mikey nsis"
     md5_hashes="['11a6ebaa644b97a22aa7ba4b5eb43e54','1aeba3bb90c6afe12ff8c78f9552aa00','def5b4919929568107ec7ae5b5dfda02']"

   strings:
      $hex_string = { 74c7bd026946000a8e03e44b611c17d876be446a818fa382fcf905cdb8e70f37333d67da8827c319685fef7a58a9a25edf512693cc322cb42040b2134a2f80b3 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}

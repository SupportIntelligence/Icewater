
rule m2319_495c12c9c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.495c12c9c4000b12"
     cluster="m2319.495c12c9c4000b12"
     cluster_size="22"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="loic flooder html"
     md5_hashes="['009db0c6096f6ee4893bae4a4392d108','10e14962be3f98a2fdbe2ae3dbf7d94a','df80bee08569d9bf21966633a728a8dd']"

   strings:
      $hex_string = { 3933575731615042794769634535366c7350756665744a6b2b7870677878634a704856694e49412f576f7a37524c4b66686c38317246645473675658544d6a5a }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}

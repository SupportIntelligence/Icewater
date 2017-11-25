
rule k3f7_15d36b44ee210b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.15d36b44ee210b32"
     cluster="k3f7.15d36b44ee210b32"
     cluster_size="34"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="hidelink html hiddenlink"
     md5_hashes="['064d382693f3ced8c89c4a0319ad5ce9','093de42e8f2fca23add8948ca1c3474a','7cf135e91cb5ef9149af8f0dc9c7b6f4']"

   strings:
      $hex_string = { 666f6e742d617765736f6d652e637373227d5d7d20293b0a2f2a205d5d3e202a2f0a3c2f7363726970743e0a3c73637269707420747970653d27746578742f6a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}

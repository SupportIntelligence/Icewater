
rule k2321_29251862dbeb1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.29251862dbeb1912"
     cluster="k2321.29251862dbeb1912"
     cluster_size="9"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus symmi vbkrypt"
     md5_hashes="['45d90c2200f3f22b87e4e634bc362792','5398cf3d3ccd871974feb6e431fb0c81','e7b400c68e0a931e442ddd63624839a3']"

   strings:
      $hex_string = { 9bd6dc1e71ce629e39e028bdd7445b2d0d5672af89b23a1aac74735b1f75b31af36435aa2257e8c8c968df6cb447f66ebc1d8e5dfb43ba4b8a0bf57a54809169 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}

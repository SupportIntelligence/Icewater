
rule m3f7_699d16c9c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.699d16c9c8000b12"
     cluster="m3f7.699d16c9c8000b12"
     cluster_size="95"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker script autolike"
     md5_hashes="['03dee549d3fd9e582a8a7b6211a2b31a','0407adfd9c7c3ff60020371b6d3f0818','32edeca7c5abb5606f061639861345f5']"

   strings:
      $hex_string = { 3d27746578742f6a617661736372697074273e0a2f2f3c215b43444154415b0a69662828646f63756d656e742e676574456c656d656e74427949642926267769 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}

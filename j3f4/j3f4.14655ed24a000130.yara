
rule j3f4_14655ed24a000130
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f4.14655ed24a000130"
     cluster="j3f4.14655ed24a000130"
     cluster_size="74"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="zusy onlinegames stealer"
     md5_hashes="['0012eaa4e41570d3b7a84425582f2336','02618351132ce345c6a2a909f292f747','27caaf8b50d840b53504b92d2041731d']"

   strings:
      $hex_string = { 6d2e5465787400456e636f64696e67006765745f415343494900476574537472696e6700496e6465784f6600537562737472696e67006f705f496e657175616c }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}


rule n3f0_224b685499a44e66
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f0.224b685499a44e66"
     cluster="n3f0.224b685499a44e66"
     cluster_size="5"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="mira uymi icgh"
     md5_hashes="['b254ad7dbad6821c6760603e035c13f5','c8b552ebf7057d6d99750a1d113270f1','e445744bd6386b60dbb9ec055dbab6c3']"

   strings:
      $hex_string = { 3dc55d3b8b9e925a0d65170c7581867576c9484d65ccc6910ea6aea019e3a346bcdd8ddef99dfbeb7eaa51436fc6df8ce980c947ba93a841bf3cd5a6cfff491f }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}

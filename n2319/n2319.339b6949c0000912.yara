
rule n2319_339b6949c0000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.339b6949c0000912"
     cluster="n2319.339b6949c0000912"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script faceliker clickjack"
     md5_hashes="['ec14efa6263ec95a4f75da2af05c31e3c985072d','f5b303210e9d84f0e2e977f80133593ad5c0807c','bbb5780eb807f2a87200e893a02093498152a833']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.339b6949c0000912"

   strings:
      $hex_string = { 747970656f6620613d3d72627d7661722063633d2f5e5b5c772b2f5f2d5d2b5b3d5d7b302c327d242f2c64633d6e756c6c3b66756e6374696f6e20656328297b }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}

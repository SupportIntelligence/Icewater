
rule j3e7_7194d6c348000310
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3e7.7194d6c348000310"
     cluster="j3e7.7194d6c348000310"
     cluster_size="391"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shedun androidos adfd"
     md5_hashes="['00dfae0fb9ac6dce137f80ebb5f6897f','014706634880d0760a201f3e0ac6e503','0a01cc445be9f3ae44377511216f7ba1']"

   strings:
      $hex_string = { 6e672f436c6173734c6f616465723b00154c6a6176612f6c616e672f457863657074696f6e3b00124c6a6176612f6c616e672f4f626a6563743b00124c6a6176 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}

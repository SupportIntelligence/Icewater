
rule m2321_33954ab9c9800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.33954ab9c9800b12"
     cluster="m2321.33954ab9c9800b12"
     cluster_size="48"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="regrun ludbaruma tinba"
     md5_hashes="['07d2344264de49def7bbc1ddef75f141','0bdab9f4fc24e1501de5b26216621cc8','4c32aefaa6b970bb69c2dc3040738790']"

   strings:
      $hex_string = { 870563a1a7fbf778803f0166381c8e42a5eaca53bdb531f92b44eeda8bd6f8487606133a42498dc1c4a610524b28b9358cd416466c0d23b485e25bc3b06de192 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}

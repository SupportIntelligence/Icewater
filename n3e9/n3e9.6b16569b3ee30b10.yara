
rule n3e9_6b16569b3ee30b10
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.6b16569b3ee30b10"
     cluster="n3e9.6b16569b3ee30b10"
     cluster_size="5"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="kryptik malicious filerepmalware"
     md5_hashes="['1249245328980b66ff1711be0666eb65','1b512701db7aa197c0d5ef546237d326','7c41a481cbef45ce0510dc3430a47081']"

   strings:
      $hex_string = { adaf87512d5d2f8457d8150d4c8c8655e1c726c20202020202020202020202c0e3da01d727acf01e526b0202020219675d0b020502020202020231d09a3a9739 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}

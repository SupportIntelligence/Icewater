
rule k2321_096d5923d9eb1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.096d5923d9eb1912"
     cluster="k2321.096d5923d9eb1912"
     cluster_size="6"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus razy autorun"
     md5_hashes="['8c6e82225796ec54eeaa7361e219f6b3','8ea062fa38fecae47021f60eb53d1508','e301091467e51830aa0099a6a038bf7b']"

   strings:
      $hex_string = { 983927d2833dfb82dd89d9e70373b30dcd8cd04258788618876679ff38dc426b1947d596b71aa171a3610a355b70c4de322e161fa4664ba92b5f4af10209bc12 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}

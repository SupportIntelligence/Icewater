
rule k3f4_3164e4069a831132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f4.3164e4069a831132"
     cluster="k3f4.3164e4069a831132"
     cluster_size="18"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="razy bladabindi backdoor"
     md5_hashes="['032ce7a89f9ee2df45cd16ab4eb2ce17','1debe0deb649aaeaa6dbaf546bc84b20','c204b7f4bc0ed2436c75394ed5088b26']"

   strings:
      $hex_string = { 41cf0262802769608d1a1c6746d274b66a294b0cd23ef30e425f702cb987d163043d2a7fec38a7ac2ac039a690c3fdf15b5655e5d49f402818f48bfbf0ad0a36 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}


rule n3e7_0b9898e1c2000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e7.0b9898e1c2000b12"
     cluster="n3e7.0b9898e1c2000b12"
     cluster_size="49"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vbkrypt bxdp malicious"
     md5_hashes="['052f7a7f8506aa8acc3499d42d5849be','30a9ede8bab3ad91b5c3ab17fda9f3ba','a44ea206e9859fb93b1a2ce1ff6fd312']"

   strings:
      $hex_string = { 9f606c7d86ce3178bc9c1d0ec9ab1f9437f6e3a5c611dc4f6ed995b077a88ba6a12155fa6bde90a4ff254d2ae2fec70de6d7cf4704d60cccbaa3430ab5a9e124 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}

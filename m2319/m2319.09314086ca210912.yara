
rule m2319_09314086ca210912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.09314086ca210912"
     cluster="m2319.09314086ca210912"
     cluster_size="5"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="script faceliker trojanclicker"
     md5_hashes="['3417c0ce3fb1fad9e39aaf86339d5f94','347fbf26242fd3361af81249ba62f865','e22abc7498a1e2740e8044c7d0a570fb']"

   strings:
      $hex_string = { 6d6173612e626c6f6773706f742e64652f323031345f30385f31395f617263686976652e68746d6c273e41756720313920283333293c2f6f7074696f6e3e0a3c }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}

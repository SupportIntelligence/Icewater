
rule m2377_11993949c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.11993949c0000b32"
     cluster="m2377.11993949c0000b32"
     cluster_size="6"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="script etaelo html"
     md5_hashes="['6cc7206de4449a482816b77cdfed14ca','7626a47151c17f0d2415428062fe16be','e7fc248be0a2b8cf701cb2d603f81077']"

   strings:
      $hex_string = { c0f6a67828c5b48deac1748c4772e7b1d064b50679db65d41dbb512c6c9e5e8e6dacaad7c7e90a2f31eb8121496ef1769c70fe09a414d28fad48a52958545310 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}

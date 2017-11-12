
rule n3e9_131d3ec9c4000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.131d3ec9c4000b32"
     cluster="n3e9.131d3ec9c4000b32"
     cluster_size="711"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="nimnul vjadtre qvod"
     md5_hashes="['026d4fcd6faf7d792c0caec6eb2830b0','02d11a99f561c36a641085d0b6649625','08c530deb3ae7e6983b1f358cac9d97b']"

   strings:
      $hex_string = { 3fd849809e044d74953292983cef1500e72c405f87a4fd736738d38316a157e0ceeaf8f94f7c1cbd87d5783b4ab1596f83a7bb72c4c4d221634bc67f99b8ab26 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}

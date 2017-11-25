
rule n3e9_3b1c93e1c6000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.3b1c93e1c6000b32"
     cluster="n3e9.3b1c93e1c6000b32"
     cluster_size="7"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dealply malicious badfile"
     md5_hashes="['27353b947e29faad84205ae78da389b3','50697732d38f99e92f6237ec03ad38fd','f39e79d48760d78089e8c1aefdd3d3ca']"

   strings:
      $hex_string = { 004578697450726f63657373000000526567436c6f73654b6579000000496d6167654c6973745f416464000000536176654443000056617269616e74436f7079 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}

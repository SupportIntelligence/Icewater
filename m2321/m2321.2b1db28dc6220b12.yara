
rule m2321_2b1db28dc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.2b1db28dc6220b12"
     cluster="m2321.2b1db28dc6220b12"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jadtre qvod pikor"
     md5_hashes="['59c74bc531d4e00e7c218e9c9dc28dcb','9651af04b0d8196dc653a0a6b4285529','ec125f469315eee708d97e70aa027450']"

   strings:
      $hex_string = { cdf162a2213ada20c25e3d29af2f64b165e9ed4627b2d131d530519d4c35e471db4e0549c72ad0b8a9ddc10073545bd8aad3b3ea78be57a401f542ae838fa11b }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}

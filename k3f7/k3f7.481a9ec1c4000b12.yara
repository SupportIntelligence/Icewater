
rule k3f7_481a9ec1c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.481a9ec1c4000b12"
     cluster="k3f7.481a9ec1c4000b12"
     cluster_size="371"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker clicker"
     md5_hashes="['007b92babe4ac1b2d5f75a312f4d3bfb','007d66defdec43a444b41f0ff42ade29','0bd5723ad4c9bfe5c63be7070926e619']"

   strings:
      $hex_string = { 643a4458496d6167655472616e73666f726d2e4d6963726f736f66742e416c706861284f7061636974793d3029273b20206d617267696e2d6c6566743a202d35 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}

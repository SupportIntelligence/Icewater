
rule m3e9_133b096992e30936
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.133b096992e30936"
     cluster="m3e9.133b096992e30936"
     cluster_size="32"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="bundler istartsurf outbrowse"
     md5_hashes="['0ff0fd4ab65a175330d09b8a7a827fbe','1070c78b411fb4d5c193cf1ef2d43d35','8022818f365ead6d366e03f37628a501']"

   strings:
      $hex_string = { 00eb0681ce00000200ba0010000085c2740681ce00000400833dd8374200010f8c8901000081e71f0308030fae5df48b45f433c984c079036a1059a900020000 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}

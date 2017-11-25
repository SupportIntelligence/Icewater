
rule n3f7_691c909dc6220b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f7.691c909dc6220b32"
     cluster="n3f7.691c909dc6220b32"
     cluster_size="168"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker clicker html"
     md5_hashes="['00db48a487c3cb0e38af4ef3cbfbb96c','0212fd13cb637d59ba828eda0454760e','179dbe8864812abebafee72a7602e833']"

   strings:
      $hex_string = { 42254532253939253830273ee79591e381aee5b08fe5b18be381abe4bd8fe38293e381a7e3828be4b889e6af9be78cab2623393739323b3c2f613e0a3c2f6c69 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}


rule m2319_3b4d6a49c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.3b4d6a49c0000b12"
     cluster="m2319.3b4d6a49c0000b12"
     cluster_size="6"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="fakejquery script classic"
     md5_hashes="['245c2112deb69a25b53d89918e0b6b81','319e9457df5725078b05a6e66431bac9','85ef8daa5fa8b987f7dc0ecb62f61099']"

   strings:
      $hex_string = { 75733a5f6c6f666d61696e2e676574456c656d656e7428272e6963652d70726576696f757327297d20293b0a0909096f626a6563742e73746172742820302c20 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}

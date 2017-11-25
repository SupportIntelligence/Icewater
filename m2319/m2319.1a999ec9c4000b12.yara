
rule m2319_1a999ec9c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.1a999ec9c4000b12"
     cluster="m2319.1a999ec9c4000b12"
     cluster_size="4"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="fakejquery script trojandownloader"
     md5_hashes="['038414435c1dbfcef5f80280bbb2c784','b6eb7a117637677c895cdedb04fa4a4f','f41491b10de8cf5cafb07d093fd16726']"

   strings:
      $hex_string = { 3a5f6c6f666d61696e2e676574456c656d656e7428272e6963652d70726576696f757327297d20293b0a0909096f626a6563742e73746172742820302c205f6c }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}

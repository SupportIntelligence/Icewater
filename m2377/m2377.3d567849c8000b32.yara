
rule m2377_3d567849c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.3d567849c8000b32"
     cluster="m2377.3d567849c8000b32"
     cluster_size="8"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="fakejquery script eiframetrojanjquery"
     md5_hashes="['284e8e3d1d8111ad0622c6dac4683621','2e2a9de7dd06debdda84ad86416a049d','ffcd95213b72a71430e059597c83d4fa']"

   strings:
      $hex_string = { 733a5f6c6f666d61696e2e676574456c656d656e7428272e6963652d70726576696f757327297d20293b0a0909096f626a6563742e73746172742820302c205f }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}

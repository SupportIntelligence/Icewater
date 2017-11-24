
rule k2318_4b1d8cc9c4000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.4b1d8cc9c4000b32"
     cluster="k2318.4b1d8cc9c4000b32"
     cluster_size="6"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker clicker"
     md5_hashes="['1c6ef82cab95450c60ad3c204505e064','2ae834e7468149b81f18be4b978857b1','a9d2e11820d754561f663da258c23269']"

   strings:
      $hex_string = { 466253686f7728293b7d293b0a6a51756572792822696e70757422292e6d6f7573656f7665722866756e6374696f6e28297b436c69636b4a61636b4662486964 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}

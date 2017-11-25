
rule k2377_491f9ec1c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2377.491f9ec1c4000b12"
     cluster="k2377.491f9ec1c4000b12"
     cluster_size="17"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171124"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker clicker"
     md5_hashes="['30540800e6a3c3cc755be0c2b28152be','36d85fc150635e1d27b41d0867bbd963','feb817190684379112d95beafab59b05']"

   strings:
      $hex_string = { 466253686f7728293b7d293b0a6a51756572792822696e70757422292e6d6f7573656f7665722866756e6374696f6e28297b436c69636b4a61636b4662486964 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}

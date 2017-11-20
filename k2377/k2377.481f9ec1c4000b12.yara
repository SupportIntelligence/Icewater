
rule k2377_481f9ec1c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2377.481f9ec1c4000b12"
     cluster="k2377.481f9ec1c4000b12"
     cluster_size="129"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker clicker"
     md5_hashes="['004a5d93647177f63f8f768b67b5b133','0143c6193241b99b83d580538dc95b5c','22499bdf6689600b4820dfe16a25722c']"

   strings:
      $hex_string = { 466253686f7728293b7d293b0a6a51756572792822696e70757422292e6d6f7573656f7665722866756e6374696f6e28297b436c69636b4a61636b4662486964 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}

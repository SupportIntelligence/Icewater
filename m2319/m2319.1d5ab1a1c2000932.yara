
rule m2319_1d5ab1a1c2000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.1d5ab1a1c2000932"
     cluster="m2319.1d5ab1a1c2000932"
     cluster_size="13"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery script trojandownloader"
     md5_hashes="['5f20866739ce7391e1a30d146198e13d9366ff2c','cea0da4e4ae1f60c8111d10b9ba473b829afaeb8','8b0d348f484ddd58a59854ef2658b0c8530325ab']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.1d5ab1a1c2000932"

   strings:
      $hex_string = { 746d702f696e7374616c6c5f346466653566333565633333362f64756d702e70687029205b3c6120687265663d2766756e6374696f6e2e696e636c756465273e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}

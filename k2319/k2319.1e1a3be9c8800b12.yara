
rule k2319_1e1a3be9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1e1a3be9c8800b12"
     cluster="k2319.1e1a3be9c8800b12"
     cluster_size="17"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['a252e350849fc1382896e01b274899888fc3197d','e1b4d929aec137b5825ba2dc2ba9322a5e43de43','30b931cf02460a38fa09d579312bb9e04a621dbd']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1e1a3be9c8800b12"

   strings:
      $hex_string = { 3045312c313139293a2838342e2c313433292929627265616b7d3b76617220613744353d7b276c3566273a22696e222c277734273a66756e6374696f6e28712c }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}

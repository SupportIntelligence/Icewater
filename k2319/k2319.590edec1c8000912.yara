
rule k2319_590edec1c8000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.590edec1c8000912"
     cluster="k2319.590edec1c8000912"
     cluster_size="50"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="diplugem script asmalwsc"
     md5_hashes="['1f0070f307ba2205d7653ab5ea3b513d93e30ce5','73676b4376e6ddbc0880afed0da79ea83254ffbf','1d87d8664f2c0271a2b98a9176d743c4fb3dc479']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.590edec1c8000912"

   strings:
      $hex_string = { 73696f222c27413535273a22656d222c27783630273a66756e6374696f6e2861297b77696e646f775b282828342e303545322c313230293c3d307842313f2837 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}

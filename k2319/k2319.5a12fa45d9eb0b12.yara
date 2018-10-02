
rule k2319_5a12fa45d9eb0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.5a12fa45d9eb0b12"
     cluster="k2319.5a12fa45d9eb0b12"
     cluster_size="7"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script browser"
     md5_hashes="['fe76ea00df660a36c29b7c7448083cfc776723ea','4ac3f3462880ab83b6c2993c05a07f49065229ba','25d598d6b8e50f7fccbd41f431e26304a539a57c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.5a12fa45d9eb0b12"

   strings:
      $hex_string = { 627265616b7d3b666f7228766172204a364c20696e20643948364c297b6966284a364c2e6c656e6774683d3d3d282831322e3945322c332e293c30783234423f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}

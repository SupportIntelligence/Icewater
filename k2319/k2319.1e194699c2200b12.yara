
rule k2319_1e194699c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1e194699c2200b12"
     cluster="k2319.1e194699c2200b12"
     cluster_size="7"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['9a6984c168d3a06245a4b35261489913fd800141','8ba650e03a3f71b695b1e1c16fbca7a32b22793f','2763360b6c95af4ab7c0ad24cd557674fd944795']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1e194699c2200b12"

   strings:
      $hex_string = { 66696e6564297b72657475726e20465b585d3b7d766172206e3d28342e333245323e28307837302c313039293f2830783139362c30786363396532643531293a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}


rule k2319_6910ea58d9bb0932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.6910ea58d9bb0932"
     cluster="k2319.6910ea58d9bb0932"
     cluster_size="8"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script browser"
     md5_hashes="['c27372f823f1a8bdaff1d94fdd29771a6a5f8427','a2811ae6499d889cf2245bd1be476afeb4b483ba','097059fd657df2a3abfb9ff80e4213d1356b4675']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.6910ea58d9bb0932"

   strings:
      $hex_string = { 5b585d213d3d756e646566696e6564297b72657475726e205a5b585d3b7d766172204f3d282830783132392c36382e293c3d28307836412c322e31394532293f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}

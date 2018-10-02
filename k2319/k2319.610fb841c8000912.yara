
rule k2319_610fb841c8000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.610fb841c8000912"
     cluster="k2319.610fb841c8000912"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="multiplug script asmalwsc"
     md5_hashes="['9bc9856544f48aef8258efa33a5086056432a9db','912b8e2785d9acab9c234f5501d25951ac3c1404','fb88a2252733e5b86f69464172d01cca49765a64']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.610fb841c8000912"

   strings:
      $hex_string = { 297b72657475726e2059213d523b7d7d3b2866756e6374696f6e28297b7661722059303d226f77222c6f353d22656e65222c54303d224c69222c7a303d226445 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}

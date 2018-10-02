
rule m2319_3110a59cdae30932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.3110a59cdae30932"
     cluster="m2319.3110a59cdae30932"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="faceliker html script"
     md5_hashes="['74d9bb4999bf3ab28e791db1dd656781c3227234','5ecd56355640e537df46ebe5d4277c433e309934','e1d4da82fcfc9e8afc4f8feafd3b79a1ae0468b3']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.3110a59cdae30932"

   strings:
      $hex_string = { 305d292c617d2c50534555444f3a66756e6374696f6e2861297b76617220622c633d21615b365d2626615b325d3b72657475726e20572e4348494c442e746573 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}

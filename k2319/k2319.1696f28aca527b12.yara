
rule k2319_1696f28aca527b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1696f28aca527b12"
     cluster="k2319.1696f28aca527b12"
     cluster_size="7"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script fffazo"
     md5_hashes="['7ca2bc43b124f61a5aedabae4472da4ab94f07bf','5bcbd2ebdce2000dc6ab66f81699b9b9d5a79244','4ebd062481e2c72d5ea240666c89e03c94a18f41']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1696f28aca527b12"

   strings:
      $hex_string = { 45322c313139293a28307838372c307838292929627265616b7d3b7661722051337a30323d7b274c396a273a332c27553964273a66756e6374696f6e284a2c55 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}

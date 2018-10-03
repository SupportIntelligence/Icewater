
rule m26bb_16b9200000000132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.16b9200000000132"
     cluster="m26bb.16b9200000000132"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="virut virtob malicious"
     md5_hashes="['142ce632636312f7d03e8c0f5a7ca0bfff60dd2a','b3ddf2bd8cecf8d79979a5b8d5750b118d29b911','1cc135732d1415897fc24546c83d29ba2f0c4d79']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.16b9200000000132"

   strings:
      $hex_string = { 7c24143bfb74278b373bf374213b5f04731c6a02ff74241456ff15fc12000183c40c85c0741083c6064385f675df33c05f5e5bc2080033c040ebf5558bec81ec }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}


rule k2319_6912e318c922e112
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.6912e318c922e112"
     cluster="k2319.6912e318c922e112"
     cluster_size="5135"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script loic flooder"
     md5_hashes="['e2d75b727979ed3101c71f3a29b23c6ae3b29b3d','f7733f1c5e310249d01dff96275c54a80101b93f','3e6b19e91d9d851cf141b9a3bd3068011965c1c2']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.6912e318c922e112"

   strings:
      $hex_string = { 2e636f6d2f696d616765733f713d74626e3a414e643947635467303977335932784858537645624774776332664f3435537538366a5a48692d75625033705155 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}

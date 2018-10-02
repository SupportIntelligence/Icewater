
rule k26bb_632950b191e72336
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26bb.632950b191e72336"
     cluster="k26bb.632950b191e72336"
     cluster_size="270"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="conduit riskware malicious"
     md5_hashes="['7c254dd120ad50fc9d36060bce44712878b9799a','7cb8f922e268ad5ae2dd0c87712976f9b93c583c','86560479ca43330c223f3c484f56e4e8073d9f47']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26bb.632950b191e72336"

   strings:
      $hex_string = { 8631eb69909e0d88e81bb6d681a8f08ad9e0e3415e47e597481da31c64dbfbaef6228dcbd279c967fc8c34ff3e98a0e4495d6c3570392106307250262afd4cc4 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}

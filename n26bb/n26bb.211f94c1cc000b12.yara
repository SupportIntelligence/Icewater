
rule n26bb_211f94c1cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.211f94c1cc000b12"
     cluster="n26bb.211f94c1cc000b12"
     cluster_size="1243"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="attribute casinoonline highconfidence"
     md5_hashes="['6ef24335971a324955375ae7014be35887c2b24d','120b0eef7035dd9ca723a98d13b0ff7986a2d190','cdf70f932a7360aa83ca2777e2219fa10b7496c5']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.211f94c1cc000b12"

   strings:
      $hex_string = { 3c3075040bc9eb022bc88d45d050ff75145157e80ce6000083c4103bc37404881eeb588b45d4483945e00f9cc183f8fc7c2d3b45147d283acb740a8a074784c0 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}


rule n2319_5114a245d5eb0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.5114a245d5eb0912"
     cluster="n2319.5114a245d5eb0912"
     cluster_size="13"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="hidelink script html"
     md5_hashes="['791c3f29d91248cce7131da2265583d19ee02db2','b2aca0b9d2764f5bcebd4ec6a3f434bd80249c07','b03db0622a41e6ee0bd7824e22ac6fd95a94d7f5']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.5114a245d5eb0912"

   strings:
      $hex_string = { 305d292c617d2c50534555444f3a66756e6374696f6e2861297b76617220622c633d21615b365d2626615b325d3b72657475726e20572e4348494c442e746573 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}

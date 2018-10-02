
rule n26bb_496a5cc1cc000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.496a5cc1cc000932"
     cluster="n26bb.496a5cc1cc000932"
     cluster_size="110"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="gandcrab ransom filerepmalware"
     md5_hashes="['ab6f6a1177b8eeb27370b146d35e1b94dee252a6','bd4814408f73998e117371cd414bc1b36559661c','a9d229f19064b8a73097685480a143fcd83ee7fa']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.496a5cc1cc000932"

   strings:
      $hex_string = { 4df051575056e82b80000083c41085c07405c60300eb558b45f4483945fc0f9cc183f8fc7c2a3bc77d2684c9740a8a064684c075f98846feff75288d45f06a01 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}

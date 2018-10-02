
rule n26d7_2b3024a5a9256f16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26d7.2b3024a5a9256f16"
     cluster="n26d7.2b3024a5a9256f16"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy malicious filerepmalware"
     md5_hashes="['f03495dd3466cab94353469b11faf9b25b2b0a19','f5f7fcbbfea490764c8968922e444d77c3057d48','215fbb971864600fce3b60989eb4eb29de80580e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26d7.2b3024a5a9256f16"

   strings:
      $hex_string = { 1bd50dacbf8c25821fbef048f7e03ac596dd84913eca8b03b1e2c8f462d0e81735dc906e2ce5d141bacd4907160f9892c1a9a520bd26e71c1994653de3eb24db }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}

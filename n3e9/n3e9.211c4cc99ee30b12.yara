
rule n3e9_211c4cc99ee30b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.211c4cc99ee30b12"
     cluster="n3e9.211c4cc99ee30b12"
     cluster_size="8"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="nimnul qvod vjadtre"
     md5_hashes="['afb022be7a77ecaf60bf5c4b845af954','b99dae44b631f6b478e4148ac3cb6a73','e8c0ccbbfdd279c1adc154dd44595fc3']"

   strings:
      $hex_string = { cfede4391cdba7a6bcbff471f1bd98507af062027e83ab6ca465b096a28a31829e0612c4c966d32a25196957f95299b11d5bd5fcfe924d9593606886b6d2aada }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}

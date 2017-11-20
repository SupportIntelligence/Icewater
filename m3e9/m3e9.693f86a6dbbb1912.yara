
rule m3e9_693f86a6dbbb1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.693f86a6dbbb1912"
     cluster="m3e9.693f86a6dbbb1912"
     cluster_size="33"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="otwycal viking wapomi"
     md5_hashes="['48711a79730dac929406802f90536838','722849e7ea560cff8eac876617a211fb','cd9e31ac719067e518aaf78260acff9b']"

   strings:
      $hex_string = { a237fc534d9c8ed0a921f6c262a823a3b326b06fe4e7115b2526b988faa1f71ffbbea405f417c31aae97cc089d2d7deed30f981caf1eeca7e80394ff7b8fb8fe }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}


rule k3e9_193471e359b2e316
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.193471e359b2e316"
     cluster="k3e9.193471e359b2e316"
     cluster_size="4"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installcore malicious unwanted"
     md5_hashes="['13a6a73d343a9eb158f39d10f97ae398','67701574952221973a1df438ec71498a','e8b85f4ecd4c0ed2e0342cb6ef1bf18a']"

   strings:
      $hex_string = { 98404c0e49834658c7fe45e3577d4ae562535d611d90232eb943007fcde68ad928eb5f5517ba1f6fca9d1bee4f80182008d895b3aac094f232d48ef3d7650bcb }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}

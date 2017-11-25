
rule j3e7_63247246d932a852
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3e7.63247246d932a852"
     cluster="j3e7.63247246d932a852"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="zusy qakbot mewsspy"
     md5_hashes="['adbe3dc866dfa095a7f1fcda60424370','c4684bb82a235d0f183dba7c0383d002','d98c01b5dd360c9943251b65a12b3eca']"

   strings:
      $hex_string = { 4d1083c7048939eb0b79064e89750ceb038d5e013b5d0c7ebe5f5e33c985c00f94c15b8bc15dc38bff558bec5185f67450803e00744b6808b9430056e8ce9cff }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}

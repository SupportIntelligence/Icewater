
rule o422_31bd208dc6620912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o422.31bd208dc6620912"
     cluster="o422.31bd208dc6620912"
     cluster_size="53548"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious coinminer gdsda"
     md5_hashes="['3c655e6c320e3c8e0bf1deb8e59b985a9d12dec9','4980b60df466cb2800a079902d7c35e559a2c206','a0c78d6e2e13cb5ea129f63bb90efe2697fd49eb']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o422.31bd208dc6620912"

   strings:
      $hex_string = { 6963616c404051414540585a003f3f314b6579496e707574436c6970626f617264496e666d7367426f78404051414540585a003f3f3152756e31506173746530 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}

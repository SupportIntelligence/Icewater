
rule k26ef_61369ce1c2000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26ef.61369ce1c2000932"
     cluster="k26ef.61369ce1c2000932"
     cluster_size="105"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="democry malicious ransom"
     md5_hashes="['25e76c4fdc84b40866452cceb3dfbaab73b414c0','c030fb3797615fdd3b68e45e2dc17f50d1044b30','21c8e7b7f027a69fd430d15dc1f8d8186430f4d5']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26ef.61369ce1c2000932"

   strings:
      $hex_string = { 44202bf97815ffc283fa0f76ec85ff7e1a85f674064183fb01741083c8ff4883c478415e415d5f5e5d5bc34c8964247066896c2442488bcd4c897c2468ba0e00 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}

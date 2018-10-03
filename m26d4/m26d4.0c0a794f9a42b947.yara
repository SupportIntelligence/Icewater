
rule m26d4_0c0a794f9a42b947
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26d4.0c0a794f9a42b947"
     cluster="m26d4.0c0a794f9a42b947"
     cluster_size="31"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="cloudatlas neoreklami malicious"
     md5_hashes="['df2e2447d3071de9c9dd524853ce41fa69034230','cb6459ed6b465858465c2a64b6fcdc033acd1ec6','ff4285b742aa87b01599f4bc1e1e485869114dd2']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26d4.0c0a794f9a42b947"

   strings:
      $hex_string = { 0033c9538b5d0c2bd843d1eb3b450c568b75100f47d985db74238bf80fb70750ffd28b55f48d7f0266890683c6028b45fc408945fc593bc375e28b7df089375e }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}

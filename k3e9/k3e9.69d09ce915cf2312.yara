
rule k3e9_69d09ce915cf2312
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.69d09ce915cf2312"
     cluster="k3e9.69d09ce915cf2312"
     cluster_size="398"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="malicious mindspark mywebsearch"
     md5_hashes="['0016ea4c6d6718448b5d3d2a63883023','00338fc42782b4e2a1d671284327c3f6','0b4a439ee3155bd69e2f52f6aef0c4af']"

   strings:
      $hex_string = { c61e8583001bf471e1ba0fe3bf2d65535e9858fdcea81f03f30b5f35624457fe82bc7533df1db5e53eae6dd1a67bf7bdf1ebb6f2277f68b8ede184eeb72a477d }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}


rule n26c9_33b11417c6230b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26c9.33b11417c6230b12"
     cluster="n26c9.33b11417c6230b12"
     cluster_size="7"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="expiro malicious filerepmalware"
     md5_hashes="['f3a8de5294847f83fbbf453bf1ad6913e2ad6e28','3ccbbff69107c2b548a2d58055c4690b061f01ab','da8866b706472b1223794d8e21fa9f64710534e2']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26c9.33b11417c6230b12"

   strings:
      $hex_string = { 6366443939740485d275590fb701662bc3663bc7770b4883c10248894c2428ebea450fb7ce4c8bc133d2488d0d67a1feffe8b2c4feff8905f0c1020044393ded }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}

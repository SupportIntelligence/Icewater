
rule n26bf_3310aa828b296992
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bf.3310aa828b296992"
     cluster="n26bf.3310aa828b296992"
     cluster_size="16"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="msilkrypt malicious dapato"
     md5_hashes="['21e37a57cff22c8dc9769d17b676f5baaa4de75f','8ce7b60ed78d4dd99b01c1d9a9dc838660c0e5f3','0c16da77733887acc7a41ed9ec5908ce2da73946']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bf.3310aa828b296992"

   strings:
      $hex_string = { c46fac71d0120cf62a673163949df03b66fe87efafb88173a58668095e2ed51043d3b1e2928e65c515f72c08cb8ff4804dde965f1a0d461f6bc81be335f140a3 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}


rule n26bf_29146c8cdabb4912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bf.29146c8cdabb4912"
     cluster="n26bf.29146c8cdabb4912"
     cluster_size="1173"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="cassiopeia malicious injector"
     md5_hashes="['91c836ba9a5c9121fdf1c924a49c433c84e79ce7','5dbe24978759589a6244936b71f601729567612c','2744a895796a1742c3adc7dc0cd1160f393ced2a']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bf.29146c8cdabb4912"

   strings:
      $hex_string = { 3bf9d4aa4677f0e09e984ada12154d9130cc568db92d248c4531a380c221f1e12be729b8c418ce25026db209f63764475c03102c41e350c61170d9a2ca4463a6 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}

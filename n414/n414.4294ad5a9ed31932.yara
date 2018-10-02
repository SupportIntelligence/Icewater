
rule n414_4294ad5a9ed31932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n414.4294ad5a9ed31932"
     cluster="n414.4294ad5a9ed31932"
     cluster_size="50"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy malicious filerepmalware"
     md5_hashes="['55d021b47ba04d79b1ae4dff34fd91a31a6328c9','7d682fe2bf90a75c449e5a61e1f27531dc5d79c0','7dc80596fe1f4e9af974932373e6f83aef0ddca9']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n414.4294ad5a9ed31932"

   strings:
      $hex_string = { 44f0bc55b58c50b3ef3fed13db7a549991fb697d41a77f9d29fe8368732a25634223dc6ffa4ccbc3e4e7c91195e80951067b0e60e38d3e12e9b6b2c88bcaffa9 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}


rule k2319_10099be9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.10099be9c8800b12"
     cluster="k2319.10099be9c8800b12"
     cluster_size="11"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik diplugem multiplug"
     md5_hashes="['6bc9719e5b7105c8a306aa6bc56c53ef99dc9978','646ecfc9c676d2e514255191042513982bf4d4d4','2b1d0476c31c0d62b3a0bd88d8e418040e94de18']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.10099be9c8800b12"

   strings:
      $hex_string = { 66696e6564297b72657475726e20515b4f5d3b7d766172205a3d2828307838342c372e36374532293c392e303545323f2839392c30786363396532643531293a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}

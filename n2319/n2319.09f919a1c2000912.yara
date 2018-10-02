
rule n2319_09f919a1c2000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.09f919a1c2000912"
     cluster="n2319.09f919a1c2000912"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="coinminer miner bitcoinminer"
     md5_hashes="['a1b1cca014567635ddc48f471e52b577c69e7d67','e2fe405808643f0639a83d81dea1d0608119f0d9','daaf19c56ef84bc5b6fb5149a11d2d6b90ef060e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.09f919a1c2000912"

   strings:
      $hex_string = { 657475726e20436f696e486976652e434f4e4649472e4c49425f55524c2b706174687d292c7761736d42696e6172793a73656c662e5741534d5f42494e415259 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}

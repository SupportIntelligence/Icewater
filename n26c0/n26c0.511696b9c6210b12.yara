
rule n26c0_511696b9c6210b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26c0.511696b9c6210b12"
     cluster="n26c0.511696b9c6210b12"
     cluster_size="1382"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="coinminer miner malicious"
     md5_hashes="['b1c7d78981fbcb5e32c8dbdc55f2d27ab97898f3','8d26b93a9c767adb53ea47c3779752407f78c7ee','53f47779ba704492bc571945d2c55525a457fa4d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26c0.511696b9c6210b12"

   strings:
      $hex_string = { d957895c24188d4e02668b0683c6026685c075f56a042bf1689c37470055d1feff15e8c3460033c983c40c85c00f94c1894c241c85c0744a83fe037c2c0fb745 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}

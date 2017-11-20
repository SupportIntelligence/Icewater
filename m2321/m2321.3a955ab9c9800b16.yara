
rule m2321_3a955ab9c9800b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.3a955ab9c9800b16"
     cluster="m2321.3a955ab9c9800b16"
     cluster_size="6"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="regrun ludbaruma tinba"
     md5_hashes="['09d2ccf6d37ff8505b27614f774f576f','86378bf413f40a3b3a4b0a8f3b407760','ebab1e7ce2b7b52b074d88d49110f385']"

   strings:
      $hex_string = { debd3ebcf87c12ffcc869b91fe1eb4d13c8197ef66edbe4ffb0cc5eae793c4eb99549264a970f167c75ca1fc2e6d79576df975cf2789d74bd9f2f45a3f2d7faa }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}

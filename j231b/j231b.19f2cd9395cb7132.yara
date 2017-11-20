
rule j231b_19f2cd9395cb7132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j231b.19f2cd9395cb7132"
     cluster="j231b.19f2cd9395cb7132"
     cluster_size="5"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family=""
     md5_hashes="['4a819ee028fa904d85131347b28225ce','72d4ca5c36e0a5d5b827a1ec63aab504','fbe44065bd978ec0752025cbcb1902cf']"

   strings:
      $hex_string = { 3c21444f43545950452068746d6c205055424c494320222d2f2f5733432f2f445444205848544d4c20312e30205472616e736974696f6e616c2f2f454e222022 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}

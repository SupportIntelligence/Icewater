
rule nfc8_211c96b9caa00b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=nfc8.211c96b9caa00b12"
     cluster="nfc8.211c96b9caa00b12"
     cluster_size="925"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="obfus banker androidos"
     md5_hashes="['083496f0221c7f925ad24d3281737cb448c5eb2f','be679ed093e2e6b2c9c865ed5bfb67a903712392','617b81d3346bcc0e6b38e97e28f7be1b9348f384']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=nfc8.211c96b9caa00b12"

   strings:
      $hex_string = { ce2b1a5daf7893575eeb7584c7d576adc5da6aa2e161a28279d9ddbe9adcf4428c748ba798c05a6ef0940ec95585c148813230bbd0e65fff8fdfc49e1c276f49 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}

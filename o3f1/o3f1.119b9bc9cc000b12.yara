
rule o3f1_119b9bc9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3f1.119b9bc9cc000b12"
     cluster="o3f1.119b9bc9cc000b12"
     cluster_size="14"
     filetype = "application/zip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="androidos hiddad mobidash"
     md5_hashes="['1b039f9683a99313448ae942d31942fb','26d24c503d603880a84184f3b19cbca0','e1df286a55a311fbda8e16574a849a32']"

   strings:
      $hex_string = { 6074524e53000c579acaebfa9b580d2299f4f5240786f9880820ced0802ce6e72de8cd8421d16926066898f86a0166f70bf3424055d2c76be928fb29c66c93d3 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}

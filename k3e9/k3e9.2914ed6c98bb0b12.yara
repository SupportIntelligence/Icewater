
rule k3e9_2914ed6c98bb0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.2914ed6c98bb0b12"
     cluster="k3e9.2914ed6c98bb0b12"
     cluster_size="8"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="zusy emotet tinba"
     md5_hashes="['1e97e5bbbecf2a9729dc9901294ea023','2595fd0609a09b312d5545a93cf75182','d6500128f50db9ec965c46e8aaa1a5ee']"

   strings:
      $hex_string = { 8be5d8d16360de07efbfd7cee7952c169785925d486225c21242b458a4944afcd52a4491607f1df6c40883d6a022bd064bc01ec4a7bc9cec575edc7ef0871f70 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}

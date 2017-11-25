
rule j3f7_39f24b9295ca6132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f7.39f24b9295ca6132"
     cluster="j3f7.39f24b9295ca6132"
     cluster_size="19"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="iframe html clicker"
     md5_hashes="['152d3b7d5abc94510e74c66b13c29608','2ca1020f4bb5136431aa77fb17383cf4','e36a3b6c22070902c5228064b7f54094']"

   strings:
      $hex_string = { 3c21444f43545950452068746d6c205055424c494320222d2f2f5733432f2f445444205848544d4c20312e30205472616e736974696f6e616c2f2f454e222022 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}

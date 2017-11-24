
rule j231b_39f24b9295ca6132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j231b.39f24b9295ca6132"
     cluster="j231b.39f24b9295ca6132"
     cluster_size="4"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="iframe html clicker"
     md5_hashes="['130af72404c585b0042afafd09d69e72','2678d4380b94fdcd189d6a9de64c9a87','6ebdc0ab1258e2a641eed1992fb912df']"

   strings:
      $hex_string = { 3c21444f43545950452068746d6c205055424c494320222d2f2f5733432f2f445444205848544d4c20312e30205472616e736974696f6e616c2f2f454e222022 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}

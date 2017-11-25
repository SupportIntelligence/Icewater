
rule k3f7_2947e449c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.2947e449c0000b32"
     cluster="k3f7.2947e449c0000b32"
     cluster_size="4"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="redirector html fakejquery"
     md5_hashes="['3e7317e0a04cf51274d7e90079a944fb','52080831daee94a9f02f4372657499b9','ca385dd8845e95d6e81f9ca1fd5cff6f']"

   strings:
      $hex_string = { 0a3c21444f43545950452068746d6c205055424c494320222d2f2f5733432f2f445444205848544d4c20312e30205472616e736974696f6e616c2f2f454e2220 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}

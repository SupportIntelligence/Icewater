
rule o3e9_31686ba1ca000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.31686ba1ca000912"
     cluster="o3e9.31686ba1ca000912"
     cluster_size="4694"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="downloadsponsor malicious unwanted"
     md5_hashes="['0001bcac20ff1133965fca7dbf7ef1dd','00072a2f033cd9ff0b57addafa45c4d7','00cc8c7d315fc4e86d74941443d22032']"

   strings:
      $hex_string = { 4d7b524f4ad14ef3815a289e10acf8bc548f6c28c54f5bf12355c52ec041712aa1e0d32355eeaa743a98c9de4727ae9ad360138f0e6afa51258692508bd04489 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}

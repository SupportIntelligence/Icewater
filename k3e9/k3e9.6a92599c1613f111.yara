
rule k3e9_6a92599c1613f111
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6a92599c1613f111"
     cluster="k3e9.6a92599c1613f111"
     cluster_size="2976"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="gamevance gkdhu adwareare"
     md5_hashes="['00023396a0d596c66093b9018960b122','0003b77217a408460226a572cbe2bf75','0118c992ec0576a3d30f94a75a8c5a80']"

   strings:
      $hex_string = { 6edd42e72f2a0767e69e1549b955c11a2ee9d9d4720609a288691cfcdbc9b293179cce3014f8d73a1045de8b026aac0dcc507d0b7cffbb19ec8ef56044b17396 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}

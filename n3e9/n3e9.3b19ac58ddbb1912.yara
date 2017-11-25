
rule n3e9_3b19ac58ddbb1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.3b19ac58ddbb1912"
     cluster="n3e9.3b19ac58ddbb1912"
     cluster_size="104"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="getnow livesoftaction riskware"
     md5_hashes="['0b7383d1270f296fbac346dfd7932c19','0cfa7d19fcaea948ab3482c4dd40aae6','3546c0f33fe44fe10a370608b767bfc7']"

   strings:
      $hex_string = { 0a5ffad21ba8188adcddcce3f198244d3b4ce5d61327904e1a8caac8e73575694082946b39d4a73358c29650e036b3b6fb9dee3e7df3ff3c21d1d7fcfdc4a66d }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}


rule k3e9_51997949c0000b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.51997949c0000b16"
     cluster="k3e9.51997949c0000b16"
     cluster_size="33"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="nitol servstart bmgfas"
     md5_hashes="['103859ec87d460fff31e9355f4d0503e','1a0989c6a9e0fadc195a18b58cd260cb','a66164b98b9f42fb98d5a5983c1d3559']"

   strings:
      $hex_string = { 53484c574150492e646c6c005553455233322e646c6c005753325f33322e646c6c0000004c6f61644c69627261727941000047657450726f6341646472657373 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}

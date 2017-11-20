
rule m2321_19b0a55adcbb0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.19b0a55adcbb0912"
     cluster="m2321.19b0a55adcbb0912"
     cluster_size="22"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="backdoor elzob shiz"
     md5_hashes="['0e881369aa5f40d75c98a23f3616b1de','10170d73de1363f47edbefd1ebe8434c','d23cd4bc33cda0aae38482e1d57f8b48']"

   strings:
      $hex_string = { b10b3992fd0a8e24bb8fa7d418bfb446d062e3d565c792cc8a97811a30e83b3dc0ab90670db84acb78775d097ef50899a90c949671a615e75776ceafe6c5f955 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}

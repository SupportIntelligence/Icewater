
rule m2321_19b0a54adcbb0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.19b0a54adcbb0912"
     cluster="m2321.19b0a54adcbb0912"
     cluster_size="31"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="backdoor elzob zusy"
     md5_hashes="['02482ab046a0854634a5330c143472b1','0aea06b2a0488f316a9e9df51a62f417','8cfd174797782476aa882f048b85cf1f']"

   strings:
      $hex_string = { b10b3992fd0a8e24bb8fa7d418bfb446d062e3d565c792cc8a97811a30e83b3dc0ab90670db84acb78775d097ef50899a90c949671a615e75776ceafe6c5f955 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}

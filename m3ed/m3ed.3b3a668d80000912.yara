
rule m3ed_3b3a668d80000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.3b3a668d80000912"
     cluster="m3ed.3b3a668d80000912"
     cluster_size="77"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit malicious nimnul"
     md5_hashes="['020bf76a4e0a990cebf890f049aaa551','023ef655cc8f3171c719d775befb9407','120ac75b7d0f18b6e2546790a35851b4']"

   strings:
      $hex_string = { da8a0284c0741e0fb6f08bce6a0123cf58d3e0c1ee038a4c35e084c1750342ebe0802200428b450c5f5e8950188bc32bc2f7d81bc023c35bc9c3ff742404e8b0 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}

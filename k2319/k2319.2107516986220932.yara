
rule k2319_2107516986220932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.2107516986220932"
     cluster="k2319.2107516986220932"
     cluster_size="19"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="multiplug kryptik diplugem"
     md5_hashes="['6f68c2fe5182c8d8d799f03c60bbbeaf70f95431','1ebb4629095a467004453d9bfe76ea0229a21928','00c36bb51963e9444b40dde16d3811a08bcc4ba8']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.2107516986220932"

   strings:
      $hex_string = { 32293a2831332e303545322c39362e292929627265616b7d3b766172204c375331683d7b2771366c273a2268222c27593942273a66756e6374696f6e284d2c51 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}


rule k3e7_3a6365668dfb5132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e7.3a6365668dfb5132"
     cluster="k3e7.3a6365668dfb5132"
     cluster_size="17"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="smforw smsspy androidos"
     md5_hashes="['0b482f50e2dd774b791f4b602970ff97','0f1f2a430e713fc7e9e0762ca47bb698','df6344cd229fdc2a844c33217dab2766']"

   strings:
      $hex_string = { 070e3c2d001702f905cc04072c02243b025f1d8a8a870304b305296903008a03a20101120f2d01141179852f030586063dc30301990354960303ec04674bb55e }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}

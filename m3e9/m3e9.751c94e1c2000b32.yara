
rule m3e9_751c94e1c2000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.751c94e1c2000b32"
     cluster="m3e9.751c94e1c2000b32"
     cluster_size="453"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['005b9d38d872c5a64d4d153e4340c5bc','0089dff445aa56057c8e6d3de8399967','046d66dc7d792c3a706b9474b9f9d2e3']"

   strings:
      $hex_string = { d223d3412bd648f7d81bc083e0f183c0110fafc603c73bd0730433c0eb0d8d45fc50515652ff158c1100018d65b05f5e5bc9c3cccccccccc8bff558bec8b4d08 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}

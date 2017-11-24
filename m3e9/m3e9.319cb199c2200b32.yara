
rule m3e9_319cb199c2200b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.319cb199c2200b32"
     cluster="m3e9.319cb199c2200b32"
     cluster_size="27"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul krap"
     md5_hashes="['17db13ff1da6bb8804d480d250161c3c','1b04e0d6a59f8f3348b29b881eb489d0','efbb912189e3b2c49e3f353a543314d3']"

   strings:
      $hex_string = { ca742a44ada00401874695820fb051654c1299e819aa1000d2defa7f6b0e9bd926033c135d0df4767a9a75c240e07c174bb49dd98f1ee4cf89c78bda2ff55b32 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}


rule m3e9_59998538c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.59998538c8800b32"
     cluster="m3e9.59998538c8800b32"
     cluster_size="23"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="upatre trojandownloader kryptik"
     md5_hashes="['0e4c9d3d2ec452c37544d6dda524be21','24218e67aaf87d34c9c357f1b487261d','c73eb94ffd72a0e65b608c8923698f00']"

   strings:
      $hex_string = { 00190064006f00650073006e0027007400200073007500700070006f00720074002000730074007200650061006d0069006e0067002900410062006a00650063 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}

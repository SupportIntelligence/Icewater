
rule k2318_311933a9c8000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.311933a9c8000932"
     cluster="k2318.311933a9c8000932"
     cluster_size="254"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="redirector iframe html"
     md5_hashes="['69514664606ae22fe17aa79b5b82184ced1de0a6','a11f6dd3c34b0bfad9f531d3d3d9e6aa26da7678','b81b45cee815138fae09847e5b835e906d22f621']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.311933a9c8000932"

   strings:
      $hex_string = { 75626d697428293b222073697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c4543544544 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}

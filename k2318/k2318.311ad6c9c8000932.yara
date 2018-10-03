
rule k2318_311ad6c9c8000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.311ad6c9c8000932"
     cluster="k2318.311ad6c9c8000932"
     cluster_size="32"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="redirector iframe html"
     md5_hashes="['1d3959158b63a539b3d44e487f80d0def63e3818','a77a02b7bb02da7ecc9e0f9e6235621d48bd1c67','7ddac4f115d61d708a906a0dff523913d920490c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.311ad6c9c8000932"

   strings:
      $hex_string = { 2e7375626d697428293b222073697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c454354 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}

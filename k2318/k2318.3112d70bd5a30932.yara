
rule k2318_3112d70bd5a30932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.3112d70bd5a30932"
     cluster="k2318.3112d70bd5a30932"
     cluster_size="7"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="redirector iframe html"
     md5_hashes="['aad6fe5947cb19fab50754b964d769b2e71e4feb','14bf19240dea698436c962fa6dc1ddcda7e7ab4b','852c340f086cb4412eda59a969d4b056a835d09c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.3112d70bd5a30932"

   strings:
      $hex_string = { 2e7375626d697428293b222073697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c454354 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}

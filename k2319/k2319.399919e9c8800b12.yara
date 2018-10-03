
rule k2319_399919e9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.399919e9c8800b12"
     cluster="k2319.399919e9c8800b12"
     cluster_size="1403"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="redirector iframe html"
     md5_hashes="['2648801170a6edb485fc5bc205057a4e9727fe98','db34c8745c7c8748f99ca2d2f4bb187bb009237f','9aa9b62c2de122c81b2a1fa66c2f98def403c288']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.399919e9c8800b12"

   strings:
      $hex_string = { 2e7375626d697428293b222073697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c454354 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}

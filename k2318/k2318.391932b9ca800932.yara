
rule k2318_391932b9ca800932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.391932b9ca800932"
     cluster="k2318.391932b9ca800932"
     cluster_size="44"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="redirector iframe html"
     md5_hashes="['160fe925035e7c1e51a4b4059b968d4bc71d51ed','e1fcd0b5636dabe7afa16614f123fedaa1c32674','2c32eceb08d15b93b773fad0a3f23294583a846c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.391932b9ca800932"

   strings:
      $hex_string = { 626d697428293b222073697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443e }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}

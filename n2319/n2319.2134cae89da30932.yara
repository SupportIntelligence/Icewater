
rule n2319_2134cae89da30932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.2134cae89da30932"
     cluster="n2319.2134cae89da30932"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="faceliker cryxos fbook"
     md5_hashes="['50adeac75a5baef01234cc2bc7da69b79c3655b3','be26148a9efa6b9df6826b5e8741fcd7c8074546','9f03d56e789cd04d4dcef334a9043274195f8a54']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.2134cae89da30932"

   strings:
      $hex_string = { 4e657720526f6d616e272c2073657269663b206c696e652d6865696768743a20313870743b5c225c75303033452e2056e1baad7920c491c6b0e1bb9d6e672078 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}

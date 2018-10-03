
rule k2318_3519b2b9ca800932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.3519b2b9ca800932"
     cluster="k2318.3519b2b9ca800932"
     cluster_size="20"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="redirector iframe html"
     md5_hashes="['84d59f6ff556b90363dbc71ba80ace54b1f341bc','4812c2fe4f89d97f23a94eba2f4046476951bccd','40320a628dea1b9f06da47525ba82c4ebee66619']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.3519b2b9ca800932"

   strings:
      $hex_string = { 75626d697428293b222073697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c4543544544 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}

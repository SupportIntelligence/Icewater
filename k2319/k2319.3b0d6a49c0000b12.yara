
rule k2319_3b0d6a49c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.3b0d6a49c0000b12"
     cluster="k2319.3b0d6a49c0000b12"
     cluster_size="29"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="redirector iframe html"
     md5_hashes="['c41feffadcdc9386ae33b9384dd27be2efd85e02','56e95f0bc500078a25fa894272b340b67c69f949','5c09e36e7443572da54a378599248a4af04a8de2']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.3b0d6a49c0000b12"

   strings:
      $hex_string = { 6e673d22302220636c6173733d22626f785f77696474685f6c656674223e0a093c74723e3c74643e3c696d67207372633d22696d616765732f7370616365722e }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}

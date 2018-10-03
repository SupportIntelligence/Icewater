
rule k2318_3112d6cdea208932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.3112d6cdea208932"
     cluster="k2318.3112d6cdea208932"
     cluster_size="19"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="redirector iframe html"
     md5_hashes="['11d4c41dd7cc70bc486fc6ead2df45c4901a2f75','707ecfe60086be36530a0e570f8998e5d08d19b9','ffec67b4011bc2cbc9e2a9e30bd3fa9362dfb909']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.3112d6cdea208932"

   strings:
      $hex_string = { 75626d697428293b222073697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c4543544544 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}


rule k2318_27335262cceb0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.27335262cceb0b12"
     cluster="k2318.27335262cceb0b12"
     cluster_size="16"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="html iframe redirector"
     md5_hashes="['12b22b2622c2fe6ff15d625c271e962dfaa761e9','f2e83d19eb6d46706c329b9840a5f27c5f1681f8','0cc4f9058510f561371f23d8e975ff3332e901dd']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.27335262cceb0b12"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}

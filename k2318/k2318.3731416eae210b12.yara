
rule k2318_3731416eae210b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.3731416eae210b12"
     cluster="k2318.3731416eae210b12"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redirector"
     md5_hashes="['c054204756ae071e8c75245bd0ad3dd1e4137bae','834d5f6e79a8f1bd360babf2367e4369d871092f','c235e5ebf593394d5b6c871fe377f93e6aa86290']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.3731416eae210b12"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}

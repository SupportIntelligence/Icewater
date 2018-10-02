
rule k2318_371adec1c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.371adec1c8000b12"
     cluster="k2318.371adec1c8000b12"
     cluster_size="82"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redir"
     md5_hashes="['8ba70c9998102149b9e0647535a3f6b3a02b2695','0c1f206fcd2b1ddeea55ecf5d5ac99e21f2beb92','81543b3aa2451a40770cab6a42ecefa9182199b7']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.371adec1c8000b12"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}

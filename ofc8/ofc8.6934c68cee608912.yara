
rule ofc8_6934c68cee608912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=ofc8.6934c68cee608912"
     cluster="ofc8.6934c68cee608912"
     cluster_size="7"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="riskware smsreg androidos"
     md5_hashes="['2de1a5530cb47b97bd9c77fe83a8aa501e1367ea','d3ab3093754cd9914a53da9d8053e9c09744d2df','a02be0db2b7f78db185380a4462fdeaebe82bff6']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=ofc8.6934c68cee608912"

   strings:
      $hex_string = { f44310a68e820762b9b2fd86a197e20958017edae3324b719e2a90050adc1ed7f3d4444f2fd27248af53b791a8654aef564668781a47dbdead39f1bf87bba9e9 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}

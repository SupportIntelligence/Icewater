
rule m26bb_251cdac1cc000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.251cdac1cc000b32"
     cluster="m26bb.251cdac1cc000b32"
     cluster_size="8"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="jaiko malicious hosts"
     md5_hashes="['e1ad584d1b159bf28b9f279f9b4b9875ec4aef7f','a7fb5996862e614e8f86d65b6c1013d3c4596370','e3cae4a4be962568df21c43edaf388968e6456db']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.251cdac1cc000b32"

   strings:
      $hex_string = { be443c0c4f66890683c60285ff7fef5f8bceb8200000002bcdd1f92bc150e8fb80000033c06689065e5d83c410c38b44240453ff74240c33db85c00f98c34b23 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}

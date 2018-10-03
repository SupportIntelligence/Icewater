
rule m26bb_217346a1ca210912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.217346a1ca210912"
     cluster="m26bb.217346a1ca210912"
     cluster_size="24"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="pmfoc loadmoney crypt"
     md5_hashes="['070eb8dd8f83eb86f13a1966824e4842e8085d5a','6713046bcdb90e1367661ea79e1ff18edaf4f7a2','8b7a5a59d463488c3a2a806e4f893fd6c53c2d97']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.217346a1ca210912"

   strings:
      $hex_string = { ca7c94d3f7d42e3efed46c87de125f7fe5f28ab1da38fab822beefc4851f7856ce6fef45660ffd0000a6ec680993b6ab35e7f67c8b237509d04e9b0a2f9521bc }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}

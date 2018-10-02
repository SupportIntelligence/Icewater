
rule m26cd_27d8e869c0800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26cd.27d8e869c0800b12"
     cluster="m26cd.27d8e869c0800b12"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="linux gafgyt backdoor"
     md5_hashes="['11679e2225f4db63c855eebf95203a023652a0be','a1852b960f3547531d404f62e3cf8b4287733c80','b34024ac1cf784d833624e44ed9f12e5faa37164']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26cd.27d8e869c0800b12"

   strings:
      $hex_string = { 786368616e676500496e76616c696420726571756573742064657363726970746f720045786368616e67652066756c6c004e6f20616e6f646500496e76616c69 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}

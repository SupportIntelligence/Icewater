
rule m3e9_7904a7469dcb4912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.7904a7469dcb4912"
     cluster="m3e9.7904a7469dcb4912"
     cluster_size="18"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vbkrypt autorun vobfus"
     md5_hashes="['2ac578755673bcc2e6d7637d18fe9591','2e0ecefbfcb64cd8c42dc0e7e3f26897','d6a7624a892d70d94067a4621706cfc9']"

   strings:
      $hex_string = { c745fc000000008b4508508b08ff51088b45fc8b4dec5f5e64890d000000005b8be55dc204009090909090909090909090558bec83ec0c68b631400064a10000 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}

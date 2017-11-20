
rule i3ed_1b9adce91dab0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i3ed.1b9adce91dab0912"
     cluster="i3ed.1b9adce91dab0912"
     cluster_size="43"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171117"
     license = "RIL-1.0 [Rick's Internet License] "
     family="backdoor padodor symmi"
     md5_hashes="['03f1d63b7cf5a9bef64e100d495388a6','0ea1b34efe9d748fe4ee776f8a9577da','a433881a8d8fb31598aacee6ddd3b6cd']"

   strings:
      $hex_string = { 7b088d0c768b348fe962ffffff31c0eb19558d6b106aff53e8a5feffff83c40c6a0be85304000083c4045d5f5e5b89ec5dc35589e5535657837d0c017505e823 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}

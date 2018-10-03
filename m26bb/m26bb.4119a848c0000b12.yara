
rule m26bb_4119a848c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.4119a848c0000b12"
     cluster="m26bb.4119a848c0000b12"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="startpage graftor malicious"
     md5_hashes="['629abbffd4801e6f03848245aa2700e20ec88ee9','2287c6ad02db8da2214d6e8c55e4ce574737fb9c','1175a9a58d5f28ad4bcffbb52dbd28c2f1391867']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.4119a848c0000b12"

   strings:
      $hex_string = { 87a1e2420004741e8a51014184d274120fb6fac1e0080bc739450c75108d71ffeb0b85f6eb0339450c75028bf14184d275c56a19e87b330000598bc65f5e5dc3 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}

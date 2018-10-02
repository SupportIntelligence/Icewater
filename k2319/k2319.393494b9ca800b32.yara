
rule k2319_393494b9ca800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.393494b9ca800b32"
     cluster="k2319.393494b9ca800b32"
     cluster_size="18"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['21c36fcf8b93a591dc027bc55241a5185a4d09b3','8914adc2ad20a3dc08aade8c3161626cea44ae1f','2d9186c7bf78a28d7006ee22079b1d4e0a1c204b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.393494b9ca800b32"

   strings:
      $hex_string = { 6566696e6564297b72657475726e204c5b6b5d3b7d76617220573d2828307834412c39293e2830783134322c3837293f22474554223a2832362c3131382e293c }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}


rule k2321_0ad0c45c5e6748ba
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.0ad0c45c5e6748ba"
     cluster="k2321.0ad0c45c5e6748ba"
     cluster_size="7"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba zusy backdoor"
     md5_hashes="['5d0686e2d1d3b34c6c023be4f6388dc3','5e33c330f3317b334e3a8a347ebed676','c16f190b547d8998c5757942f842806f']"

   strings:
      $hex_string = { cce5f1718e1ebc3c9373e936112a2f507434a625379610d166a51a91edb2d9281400ba6a69b75aa19fbf977f9d40acd0f2ef2ebd6182ea39eb70037230463188 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
